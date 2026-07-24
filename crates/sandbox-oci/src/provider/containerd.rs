use super::writable::LoopbackWritableRootfs;
use super::{
    command::CommandRunner,
    config::{canonical_child, ContainerdProviderConfig, ImagePlatform},
    handle::ProviderMetadata,
    layer::{validate_layer, LayerBudget},
    validation::{
        measure_rootfs, mount_is_read_only, mount_state, valid_digest, validate_locked_image,
        validate_platform, RootfsMeasurement,
    },
    GarbageCollectionReport, ImageProvider, ImmutableRootfs, PreparationStatus,
    PreparedImageHandle, RegistryCredential, WritableRootfs, WritableRootfsExport,
    WritableRootfsIdentity,
};
use crate::{
    compiler::verify_lock, io_error, LockedDescriptor, LockedImage, SandboxError, TopologyLock,
};
use serde_json::Value;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use tempfile::Builder;

const PROVIDER_ID: &str = "containerd-v1";
const INDEX_MEDIA_TYPES: &[&str] = &[
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
];
const MANIFEST_MEDIA_TYPES: &[&str] = &[
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
];

pub struct ContainerdImageProvider {
    config: ContainerdProviderConfig,
    runner: CommandRunner,
    writable: Option<LoopbackWritableRootfs>,
    fixed_rootfs: Option<PathBuf>,
    fixed_image: Option<LockedImage>,
    operation: Mutex<()>,
}

impl ContainerdImageProvider {
    pub fn new(config: ContainerdProviderConfig) -> Result<Self, SandboxError> {
        let config = config.validated()?;
        let fixed_rootfs = config
            .fixed_rootfs
            .as_ref()
            .map(|fixed| fixed.rootfs.clone());
        let fixed_image = config
            .fixed_rootfs
            .as_ref()
            .map(|fixed| load_fixed_image(&fixed.topology_lock))
            .transpose()?;
        let writable = if fixed_rootfs.is_some() {
            None
        } else {
            Some(LoopbackWritableRootfs::new(
                config.writable_rootfs.clone(),
                config.limits.maximum_command_output_bytes,
            )?)
        };
        let runner = CommandRunner::new(
            config.ctr_program.clone(),
            config.address.clone(),
            config.namespace.clone(),
            config.limits.maximum_command_output_bytes,
        );
        if fixed_rootfs.is_none() {
            runner.run(
                &["version".to_owned()],
                Duration::from_secs(10),
                "query containerd version",
            )?;
        }
        let provider = Self {
            config,
            runner,
            writable,
            fixed_rootfs,
            fixed_image,
            operation: Mutex::new(()),
        };
        if provider.fixed_rootfs.is_none() {
            provider.ensure_namespace()?;
            provider.garbage_collect()?;
        }
        Ok(provider)
    }

    #[must_use]
    pub fn config(&self) -> &ContainerdProviderConfig {
        &self.config
    }

    fn validate_image(&self, image: &LockedImage) -> Result<(), SandboxError> {
        validate_locked_image(image, &self.config.limits)?;
        validate_platform(image, &self.config.platform)?;
        if self
            .fixed_image
            .as_ref()
            .is_some_and(|expected| image != expected)
        {
            return Err(SandboxError::ImageProvider(
                "locked image does not match the image bound to the fixed rootfs".to_owned(),
            ));
        }
        Ok(())
    }

    fn fixed_measurement(&self) -> Option<RootfsMeasurement> {
        self.config
            .fixed_rootfs
            .as_ref()
            .and_then(|fixed| fixed.measurement.as_ref())
            .map(|measurement| RootfsMeasurement {
                digest: measurement.digest.clone(),
                entries: measurement.entries,
                bytes: measurement.bytes,
            })
    }

    fn ensure_namespace(&self) -> Result<(), SandboxError> {
        let listed = self.runner.run(
            &[
                "namespaces".to_owned(),
                "list".to_owned(),
                "--quiet".to_owned(),
            ],
            Duration::from_secs(10),
            "list containerd namespaces",
        )?;
        if String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|namespace| namespace == self.config.namespace)
        {
            return Ok(());
        }
        self.runner.run(
            &[
                "namespaces".to_owned(),
                "create".to_owned(),
                self.config.namespace.clone(),
            ],
            Duration::from_secs(10),
            "create containerd namespace",
        )?;
        Ok(())
    }

    fn resolve_remote(
        &self,
        source: &str,
        credential: Option<&RegistryCredential>,
    ) -> Result<LockedImage, SandboxError> {
        let reference = parse_reference(source)?;
        if let Some(credential) = credential {
            credential.ensure_registry(reference.registry)?;
        }
        let credentials = self.credential_directory(source, credential)?;
        let mut arguments = vec![
            "content".to_owned(),
            "fetch".to_owned(),
            "--metadata-only".to_owned(),
            "--platform".to_owned(),
            self.config.platform.as_containerd_platform(),
            "--label".to_owned(),
            "runtrue.io/managed=true".to_owned(),
        ];
        if let Some(directory) = credentials.as_ref().map(tempfile::TempDir::path) {
            arguments.push("--hosts-dir".to_owned());
            arguments.push(directory.display().to_string());
        }
        arguments.extend([source.to_owned(), source.to_owned()]);
        let fetched = self.runner.run(
            &arguments,
            self.config.limits.operation_timeout,
            "resolve OCI metadata through containerd",
        );
        drop(credentials);
        fetched?;

        let record = self.runner.run(
            &[
                "images".to_owned(),
                "list".to_owned(),
                format!("name=={source}"),
            ],
            Duration::from_secs(10),
            "read resolved containerd image",
        )?;
        let (top_media_type, top_digest) = image_record(source, &record.stdout)?;
        let (top_content, top_observed) = self.runner.read_content(
            &top_digest,
            self.config.limits.maximum_manifest_bytes,
            self.config.limits.operation_timeout,
        )?;
        let top_descriptor = LockedDescriptor {
            media_type: top_media_type,
            digest: top_digest,
            size: top_observed.bytes,
        };
        let top = metadata_value(
            "image metadata",
            &top_content.bytes,
            &top_descriptor.media_type,
        )?;
        let (index, manifest) = if is_index_media_type(&top_descriptor.media_type) {
            let manifests = required_field(&top, "manifests")?
                .as_array()
                .ok_or_else(|| {
                    SandboxError::ImageProvider("OCI index manifests are not an array".to_owned())
                })?;
            let selected = manifests
                .iter()
                .filter(|candidate| platform_matches(candidate, &self.config.platform))
                .map(json_descriptor)
                .collect::<Result<Vec<_>, _>>()?;
            if selected.len() != 1 {
                return Err(SandboxError::ImageProvider(format!(
                    "OCI index does not contain exactly one {} manifest",
                    self.config.platform.as_containerd_platform()
                )));
            }
            (Some(top_descriptor), selected[0].clone())
        } else if is_manifest_media_type(&top_descriptor.media_type) {
            (None, top_descriptor)
        } else {
            return Err(SandboxError::ImageProvider(
                "resolved OCI object is not an image manifest or index".to_owned(),
            ));
        };

        let manifest_bytes = self
            .runner
            .verified_content(
                &manifest.digest,
                manifest.size,
                self.config.limits.maximum_manifest_bytes,
                self.config.limits.operation_timeout,
            )?
            .bytes;
        let manifest_value = metadata_value("manifest", &manifest_bytes, &manifest.media_type)?;
        if manifest_value
            .get("artifactType")
            .is_some_and(|value| !value.is_null())
        {
            return Err(SandboxError::ImageProvider(
                "OCI artifacts are not admitted as container images".to_owned(),
            ));
        }
        let config = json_descriptor(required_field(&manifest_value, "config")?)?;
        let layers = required_field(&manifest_value, "layers")?
            .as_array()
            .ok_or_else(|| {
                SandboxError::ImageProvider("OCI manifest layers are not an array".to_owned())
            })?
            .iter()
            .map(json_descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        let config_bytes = self
            .runner
            .verified_content(
                &config.digest,
                config.size,
                self.config.limits.maximum_config_bytes,
                self.config.limits.operation_timeout,
            )?
            .bytes;
        let config_value: Value = serde_json::from_slice(&config_bytes).map_err(|error| {
            SandboxError::ImageProvider(format!("decode verified OCI config: {error}"))
        })?;
        let image = LockedImage {
            source: source.to_owned(),
            exact_reference: format!("{}@{}", reference.repository, manifest.digest),
            image_id: config.digest.clone(),
            index,
            manifest,
            config,
            layers,
            operating_system: string_field(&config_value, "os")?,
            architecture: string_field(&config_value, "architecture")?,
            variant: self.config.platform.variant.clone(),
        };
        self.validate_image(&image)?;
        Ok(image)
    }

    fn pull_arguments(
        &self,
        image: &LockedImage,
        credential_directory: Option<&Path>,
    ) -> Result<Vec<String>, SandboxError> {
        let mut arguments = vec![
            "images".to_owned(),
            "pull".to_owned(),
            "--local".to_owned(),
            "--sync-fs".to_owned(),
            "--max-concurrent-downloads".to_owned(),
            "3".to_owned(),
            "--platform".to_owned(),
            self.config.platform.as_containerd_platform(),
            "--snapshotter".to_owned(),
            self.config.snapshotter.clone(),
            "--label".to_owned(),
            "runtrue.io/managed=true".to_owned(),
        ];
        if let Some(directory) = credential_directory {
            arguments.push("--hosts-dir".to_owned());
            arguments.push(directory.display().to_string());
        }
        arguments.push(containerd_reference(image)?);
        Ok(arguments)
    }

    fn fetch_arguments(
        &self,
        image: &LockedImage,
        credential_directory: Option<&Path>,
    ) -> Result<Vec<String>, SandboxError> {
        let reference = containerd_reference(image)?;
        let mut arguments = vec![
            "content".to_owned(),
            "fetch".to_owned(),
            "--platform".to_owned(),
            self.config.platform.as_containerd_platform(),
            "--label".to_owned(),
            "runtrue.io/managed=true".to_owned(),
        ];
        if let Some(directory) = credential_directory {
            arguments.push("--hosts-dir".to_owned());
            arguments.push(directory.display().to_string());
        }
        arguments.extend([reference.clone(), reference]);
        Ok(arguments)
    }

    fn credential_directory(
        &self,
        source: &str,
        credential: Option<&RegistryCredential>,
    ) -> Result<Option<tempfile::TempDir>, SandboxError> {
        let Some(credential) = credential else {
            return Ok(None);
        };
        let reference = parse_reference(source)?;
        credential.ensure_registry(reference.registry)?;
        let temporary = Builder::new()
            .prefix(".credentials-")
            .tempdir_in(&self.config.mount_root)
            .map_err(|source| io_error(&self.config.mount_root, source))?;
        fs::set_permissions(
            temporary.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .map_err(|source| io_error(temporary.path(), source))?;
        let registry = reference.registry;
        let directory = temporary.path().join(registry);
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|source| io_error(&directory, source))?;
        let endpoint = if registry == "docker.io" {
            "registry-1.docker.io".to_owned()
        } else {
            registry.to_owned()
        };
        let header =
            serde_json::to_string(&credential.authorization_header()).map_err(|error| {
                SandboxError::ImageProvider(format!(
                    "encode registry authorization header: {error}"
                ))
            })?;
        let contents = format!(
            "server = \"https://{endpoint}\"\n\n[host.\"https://{endpoint}\"]\n  capabilities = [\"pull\", \"resolve\"]\n  [host.\"https://{endpoint}\".header]\n    authorization = {header}\n"
        );
        let path = directory.join("hosts.toml");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        file.write_all(contents.as_bytes())
            .map_err(|source| io_error(&path, source))?;
        file.sync_all().map_err(|source| io_error(&path, source))?;
        Ok(Some(temporary))
    }

    fn verified_metadata(
        &self,
        descriptor: &LockedDescriptor,
        maximum: u64,
    ) -> Result<Vec<u8>, SandboxError> {
        Ok(self
            .runner
            .verified_content(
                &descriptor.digest,
                descriptor.size,
                maximum,
                self.config.limits.operation_timeout,
            )?
            .bytes)
    }

    fn verify_descriptor_graph(&self, image: &LockedImage) -> Result<(), SandboxError> {
        let manifest_bytes =
            self.verified_metadata(&image.manifest, self.config.limits.maximum_manifest_bytes)?;
        let manifest = metadata_value("manifest", &manifest_bytes, &image.manifest.media_type)?;
        let config = json_descriptor(required_field(&manifest, "config")?)?;
        let layers = required_field(&manifest, "layers")?
            .as_array()
            .ok_or_else(|| {
                SandboxError::ImageProvider("OCI manifest layers are not an array".to_owned())
            })?
            .iter()
            .map(json_descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        if config != image.config || layers != image.layers {
            return Err(SandboxError::ImageProvider(
                "OCI manifest descriptor graph does not match the topology lock".to_owned(),
            ));
        }

        let config_bytes =
            self.verified_metadata(&image.config, self.config.limits.maximum_config_bytes)?;
        let config_value: Value = serde_json::from_slice(&config_bytes).map_err(|error| {
            SandboxError::ImageProvider(format!("decode verified OCI config: {error}"))
        })?;
        if string_field(&config_value, "os")? != image.operating_system
            || string_field(&config_value, "architecture")? != image.architecture
        {
            return Err(SandboxError::ImageProvider(
                "OCI config platform does not match the topology lock".to_owned(),
            ));
        }

        if let Some(index) = &image.index {
            let index_bytes =
                self.verified_metadata(index, self.config.limits.maximum_manifest_bytes)?;
            let index_value = metadata_value("index", &index_bytes, &index.media_type)?;
            let manifests = required_field(&index_value, "manifests")?
                .as_array()
                .ok_or_else(|| {
                    SandboxError::ImageProvider("OCI index manifests are not an array".to_owned())
                })?;
            let matches = manifests
                .iter()
                .filter(|candidate| platform_matches(candidate, &self.config.platform))
                .map(json_descriptor)
                .collect::<Result<Vec<_>, _>>()?;
            if matches.len() != 1 || matches.first() != Some(&image.manifest) {
                return Err(SandboxError::ImageProvider(
                    "OCI index does not select exactly the locked platform manifest".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_layers(&self, image: &LockedImage) -> Result<(), SandboxError> {
        let deadline = std::time::Instant::now() + self.config.limits.operation_timeout;
        let mut budget = LayerBudget::default();
        for layer in &image.layers {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(SandboxError::Timeout(
                    "validate OCI image layers".to_owned(),
                ));
            }
            self.runner.inspect_content(
                &layer.digest,
                layer.size,
                self.config.limits.maximum_compressed_bytes,
                remaining,
                |reader| validate_layer(reader, layer, &self.config.limits, &mut budget, deadline),
            )?;
        }
        Ok(())
    }

    fn activation_directory(&self, activation_key: &str) -> PathBuf {
        self.config
            .mount_root
            .join("activations")
            .join(activation_key)
    }

    fn measurement_path(&self, activation_key: &str) -> PathBuf {
        self.config
            .mount_root
            .join("measurements")
            .join(format!("{activation_key}.json"))
    }

    fn read_metadata(&self, path: &Path) -> Result<ProviderMetadata, SandboxError> {
        let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
        serde_json::from_slice(&bytes).map_err(|error| {
            SandboxError::ImageProvider(format!("decode provider metadata: {error}"))
        })
    }

    fn write_metadata(
        &self,
        directory: &Path,
        path: &Path,
        metadata: &ProviderMetadata,
    ) -> Result<(), SandboxError> {
        let bytes = serde_json::to_vec_pretty(metadata).map_err(|error| {
            SandboxError::ImageProvider(format!("encode provider metadata: {error}"))
        })?;
        let temporary = Builder::new()
            .prefix(".image-")
            .tempfile_in(directory)
            .map_err(|source| io_error(directory, source))?;
        temporary
            .as_file()
            .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|source| io_error(temporary.path(), source))?;
        temporary
            .as_file()
            .write_all(&bytes)
            .map_err(|source| io_error(temporary.path(), source))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| io_error(temporary.path(), source))?;
        temporary
            .persist(path)
            .map_err(|error| io_error(path, error.error))?;
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(directory, source))
    }

    fn cached_measurement(
        &self,
        image: &LockedImage,
        activation_key: &str,
    ) -> Result<Option<ProviderMetadata>, SandboxError> {
        let path = self.measurement_path(activation_key);
        if !path.is_file() {
            return Ok(None);
        }
        let metadata = self.read_metadata(&path)?;
        if !metadata.matches(PROVIDER_ID, activation_key, image)
            || !valid_digest(&metadata.rootfs_digest)
            || metadata.rootfs_entries > self.config.limits.maximum_entries
            || metadata.rootfs_bytes > self.config.limits.maximum_expanded_bytes
        {
            return Err(SandboxError::ImageProvider(
                "cached rootfs measurement does not match the locked image".to_owned(),
            ));
        }
        Ok(Some(metadata))
    }

    fn rootfs_from_metadata(
        &self,
        image: &LockedImage,
        activation_key: &str,
        directory: &Path,
    ) -> Result<Option<ImmutableRootfs>, SandboxError> {
        let metadata_path = directory.join("image.json");
        if !metadata_path.is_file() {
            return Ok(None);
        }
        let metadata = self.read_metadata(&metadata_path)?;
        if !metadata.matches(PROVIDER_ID, activation_key, image) {
            return Err(SandboxError::ImageProvider(
                "provider metadata does not match the locked image".to_owned(),
            ));
        }
        let rootfs = canonical_child(&self.config.mount_root, &directory.join("rootfs"))?;
        if !mount_is_read_only(&rootfs)? {
            return Err(SandboxError::ImageProvider(
                "provider rootfs is not an active read-only mount".to_owned(),
            ));
        }
        if !valid_digest(&metadata.rootfs_digest)
            || metadata.rootfs_entries > self.config.limits.maximum_entries
            || metadata.rootfs_bytes > self.config.limits.maximum_expanded_bytes
        {
            return Err(SandboxError::ImageProvider(
                "provider rootfs metadata exceeds policy".to_owned(),
            ));
        }
        Ok(Some(ImmutableRootfs {
            provider: PROVIDER_ID.to_owned(),
            activation_key: activation_key.to_owned(),
            image: image.clone(),
            rootfs,
            rootfs_digest: metadata.rootfs_digest,
            rootfs_entries: metadata.rootfs_entries,
            rootfs_bytes: metadata.rootfs_bytes,
        }))
    }

    fn cleanup_activation(&self, directory: &Path) -> Result<bool, SandboxError> {
        let rootfs = directory.join("rootfs");
        let mounted = mount_state(&rootfs)?.is_some();
        if mounted {
            self.runner.run(
                &[
                    "images".to_owned(),
                    "unmount".to_owned(),
                    "--snapshotter".to_owned(),
                    self.config.snapshotter.clone(),
                    "--rm".to_owned(),
                    rootfs.display().to_string(),
                ],
                self.config.limits.operation_timeout,
                "unmount containerd image",
            )?;
        }
        if directory.exists() {
            fs::remove_dir_all(directory).map_err(|source| io_error(directory, source))?;
        }
        Ok(mounted)
    }

    fn initialize_runtime_files(&self, rootfs: &Path) -> Result<(), SandboxError> {
        let etc = rootfs.join("etc");
        match fs::symlink_metadata(&etc) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(SandboxError::ImageProvider(
                    "image rootfs `/etc` is not a directory".to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o755)
                    .create(&etc)
                    .map_err(|source| io_error(&etc, source))?;
            }
            Err(source) => return Err(io_error(&etc, source)),
        }
        for name in ["hosts", "resolv.conf"] {
            let path = etc.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                Ok(_) => {
                    return Err(SandboxError::ImageProvider(format!(
                        "image rootfs `/etc/{name}` is not a regular file"
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o644)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path)
                        .map_err(|source| io_error(&path, source))?;
                    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))
                        .map_err(|source| io_error(&path, source))?;
                    file.sync_all().map_err(|source| io_error(&path, source))?;
                }
                Err(source) => return Err(io_error(&path, source)),
            }
        }
        remount_read_only(rootfs)
    }
}

impl ImageProvider for ContainerdImageProvider {
    fn resolve(
        &self,
        source: &str,
        credential: Option<&RegistryCredential>,
    ) -> Result<LockedImage, SandboxError> {
        if self.fixed_rootfs.is_some() {
            return Err(SandboxError::Unsupported(format!(
                "fixed-rootfs image provider cannot resolve `{source}`"
            )));
        }
        self.resolve_remote(source, credential)
    }

    fn pull(
        &self,
        image: &LockedImage,
        credential: Option<&RegistryCredential>,
    ) -> Result<PreparationStatus, SandboxError> {
        self.validate_image(image)?;
        if self.fixed_rootfs.is_some() {
            return Ok(PreparationStatus::Reused);
        }
        let _operation = self.operation.lock().expect("image provider lock");
        if self.verify(image).is_ok() && self.unpack(image).is_ok() {
            return Ok(PreparationStatus::Reused);
        }
        let credentials = self.credential_directory(&image.exact_reference, credential)?;
        let credential_path = credentials.as_ref().map(tempfile::TempDir::path);
        let fetched = self.runner.run(
            &self.fetch_arguments(image, credential_path)?,
            self.config.limits.operation_timeout,
            "fetch pinned OCI image content",
        );
        if let Err(error) = fetched {
            drop(credentials);
            return Err(error);
        }
        self.verify(image)?;
        let result = self.runner.run(
            &self.pull_arguments(image, credential_path)?,
            self.config.limits.operation_timeout,
            "unpack verified OCI image",
        );
        drop(credentials);
        result?;
        self.unpack(image)?;
        Ok(PreparationStatus::Prepared)
    }

    fn verify(&self, image: &LockedImage) -> Result<(), SandboxError> {
        self.validate_image(image)?;
        if self.fixed_rootfs.is_some() {
            return Ok(());
        }
        self.verify_descriptor_graph(image)?;
        self.validate_layers(image)
    }

    fn unpack(&self, image: &LockedImage) -> Result<(), SandboxError> {
        self.validate_image(image)?;
        if self.fixed_rootfs.is_some() {
            return Ok(());
        }
        let ready_reference = containerd_reference(image)?;
        let result = self.runner.run(
            &[
                "images".to_owned(),
                "check".to_owned(),
                "--quiet".to_owned(),
                "--snapshotter".to_owned(),
                self.config.snapshotter.clone(),
                format!("name=={ready_reference}"),
            ],
            self.config.limits.operation_timeout,
            "check unpacked containerd image",
        )?;
        if !String::from_utf8_lossy(&result.stdout)
            .lines()
            .any(|reference| reference == ready_reference)
        {
            return Err(SandboxError::ImageProvider(
                "containerd image is not completely downloaded and unpacked".to_owned(),
            ));
        }
        Ok(())
    }

    fn activate(&self, image: &LockedImage) -> Result<PreparedImageHandle, SandboxError> {
        self.validate_image(image)?;
        Ok(PreparedImageHandle {
            provider: PROVIDER_ID.to_owned(),
            activation_key: digest_key(&image.manifest.digest)?,
            image: image.clone(),
        })
    }

    fn mount(&self, handle: &PreparedImageHandle) -> Result<ImmutableRootfs, SandboxError> {
        if handle.provider != PROVIDER_ID {
            return Err(SandboxError::ImageProvider(
                "prepared image handle belongs to another provider".to_owned(),
            ));
        }
        self.validate_image(&handle.image)?;
        if let Some(rootfs) = &self.fixed_rootfs {
            let measured = match self.fixed_measurement() {
                Some(measured) => measured,
                None => measure_rootfs(rootfs, &self.config.limits)?,
            };
            return Ok(ImmutableRootfs {
                provider: PROVIDER_ID.to_owned(),
                activation_key: handle.activation_key.clone(),
                image: handle.image.clone(),
                rootfs: rootfs.clone(),
                rootfs_digest: measured.digest,
                rootfs_entries: measured.entries,
                rootfs_bytes: measured.bytes,
            });
        }
        let _operation = self.operation.lock().expect("image provider lock");
        let activations = self.config.mount_root.join("activations");
        fs::create_dir_all(&activations).map_err(|source| io_error(&activations, source))?;
        let directory = self.activation_directory(&handle.activation_key);
        if directory.exists() {
            match self.rootfs_from_metadata(&handle.image, &handle.activation_key, &directory) {
                Ok(Some(rootfs)) => return Ok(rootfs),
                Ok(None) | Err(_) => {
                    self.cleanup_activation(&directory)?;
                }
            }
        }
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|source| io_error(&directory, source))?;
        let rootfs = directory.join("rootfs");
        DirBuilder::new()
            .mode(0o755)
            .create(&rootfs)
            .map_err(|source| io_error(&rootfs, source))?;
        let mount_arguments = [
            "images".to_owned(),
            "mount".to_owned(),
            "--rw".to_owned(),
            "--snapshotter".to_owned(),
            self.config.snapshotter.clone(),
            "--platform".to_owned(),
            self.config.platform.as_containerd_platform(),
            containerd_reference(&handle.image)?,
            rootfs.display().to_string(),
        ];
        let deadline = Instant::now()
            .checked_add(self.config.limits.operation_timeout)
            .ok_or_else(|| SandboxError::Timeout("mount immutable containerd image".to_owned()))?;
        let mounted = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(SandboxError::Timeout(
                    "mount immutable containerd image".to_owned(),
                ));
            }
            let attempt = self.runner.run(
                &mount_arguments,
                remaining,
                "mount immutable containerd image",
            );
            if !attempt
                .as_ref()
                .is_err_and(|error| error.to_string().contains("bucket already exists"))
            {
                break attempt;
            }
            std::thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
        };
        if let Err(error) = mounted {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        let result = (|| {
            let canonical = canonical_child(&self.config.mount_root, &rootfs)?;
            self.initialize_runtime_files(&canonical)?;
            if !mount_is_read_only(&canonical)? {
                return Err(SandboxError::ImageProvider(
                    "containerd mounted an image without read-only enforcement".to_owned(),
                ));
            }
            let cached = self.cached_measurement(&handle.image, &handle.activation_key)?;
            let measurement_was_cached = cached.is_some();
            let immutable = if let Some(metadata) = cached {
                ImmutableRootfs {
                    provider: PROVIDER_ID.to_owned(),
                    activation_key: handle.activation_key.clone(),
                    image: handle.image.clone(),
                    rootfs: canonical,
                    rootfs_digest: metadata.rootfs_digest,
                    rootfs_entries: metadata.rootfs_entries,
                    rootfs_bytes: metadata.rootfs_bytes,
                }
            } else {
                let measured = measure_rootfs(&canonical, &self.config.limits)?;
                ImmutableRootfs {
                    provider: PROVIDER_ID.to_owned(),
                    activation_key: handle.activation_key.clone(),
                    image: handle.image.clone(),
                    rootfs: canonical,
                    rootfs_digest: measured.digest,
                    rootfs_entries: measured.entries,
                    rootfs_bytes: measured.bytes,
                }
            };
            let metadata = ProviderMetadata::from_rootfs(&immutable);
            if !measurement_was_cached {
                let measurements = self.config.mount_root.join("measurements");
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&measurements)
                    .map_err(|source| io_error(&measurements, source))?;
                self.write_metadata(
                    &measurements,
                    &self.measurement_path(&handle.activation_key),
                    &metadata,
                )?;
            }
            self.write_metadata(&directory, &directory.join("image.json"), &metadata)?;
            Ok(immutable)
        })();
        if result.is_err() {
            let _ = self.cleanup_activation(&directory);
        }
        result
    }

    fn release(&self, rootfs: &ImmutableRootfs) -> Result<(), SandboxError> {
        if rootfs.provider != PROVIDER_ID
            || rootfs.activation_key != digest_key(&rootfs.image.manifest.digest)?
        {
            return Err(SandboxError::ImageProvider(
                "immutable rootfs handle belongs to another provider".to_owned(),
            ));
        }
        if let Some(fixed_rootfs) = &self.fixed_rootfs {
            if &rootfs.rootfs != fixed_rootfs {
                return Err(SandboxError::ImageProvider(
                    "fixed rootfs path does not match its provider handle".to_owned(),
                ));
            }
            return Ok(());
        }
        let _operation = self.operation.lock().expect("image provider lock");
        let directory = self.activation_directory(&rootfs.activation_key);
        let expected = directory.join("rootfs");
        if rootfs.rootfs != fs::canonicalize(&expected).unwrap_or(expected) {
            return Err(SandboxError::ImageProvider(
                "immutable rootfs path does not match its provider handle".to_owned(),
            ));
        }
        self.cleanup_activation(&directory)?;
        Ok(())
    }

    fn create_writable_rootfs(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
    ) -> Result<WritableRootfs, SandboxError> {
        if self.fixed_rootfs.is_some() {
            return Err(SandboxError::Unsupported(
                "fixed-rootfs image provider supports read-only roots only".to_owned(),
            ));
        }
        let _operation = self.operation.lock().expect("image provider lock");
        self.writable
            .as_ref()
            .expect("dynamic provider has a writable-root provider")
            .create(immutable, identity, quota_bytes)
    }

    fn release_writable_rootfs(&self, rootfs: &WritableRootfs) -> Result<(), SandboxError> {
        let Some(writable) = &self.writable else {
            return Err(SandboxError::Unsupported(
                "fixed-rootfs image provider has no writable roots".to_owned(),
            ));
        };
        let _operation = self.operation.lock().expect("image provider lock");
        writable.release(rootfs)
    }

    fn export_writable_rootfs(
        &self,
        rootfs: &WritableRootfs,
        destination: &Path,
    ) -> Result<WritableRootfsExport, SandboxError> {
        let Some(writable) = &self.writable else {
            return Err(SandboxError::Unsupported(
                "fixed-rootfs image provider has no writable roots".to_owned(),
            ));
        };
        let _operation = self.operation.lock().expect("image provider lock");
        writable.export(rootfs, destination)
    }

    fn restore_writable_rootfs(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
        diff: &Path,
    ) -> Result<WritableRootfs, SandboxError> {
        if self.fixed_rootfs.is_some() {
            return Err(SandboxError::Unsupported(
                "fixed-rootfs image provider cannot restore writable roots".to_owned(),
            ));
        }
        let _operation = self.operation.lock().expect("image provider lock");
        self.writable
            .as_ref()
            .expect("dynamic provider has a writable-root provider")
            .restore(immutable, identity, quota_bytes, diff)
    }

    fn garbage_collect(&self) -> Result<GarbageCollectionReport, SandboxError> {
        if self.fixed_rootfs.is_some() {
            return Ok(GarbageCollectionReport {
                stale_staging_directories: 0,
                stale_mounts: 0,
                stale_writable_roots: 0,
            });
        }
        let _operation = self.operation.lock().expect("image provider lock");
        let mut report = GarbageCollectionReport {
            stale_staging_directories: 0,
            stale_mounts: 0,
            stale_writable_roots: self
                .writable
                .as_ref()
                .expect("dynamic provider has a writable-root provider")
                .garbage_collect()?,
        };
        for entry in fs::read_dir(&self.config.mount_root)
            .map_err(|source| io_error(&self.config.mount_root, source))?
        {
            let entry = entry.map_err(|source| io_error(&self.config.mount_root, source))?;
            if entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".credentials-")
            {
                fs::remove_dir_all(entry.path())
                    .map_err(|source| io_error(entry.path(), source))?;
                report.stale_staging_directories += 1;
            }
        }
        let activations = self.config.mount_root.join("activations");
        if !activations.exists() {
            return Ok(report);
        }
        for entry in fs::read_dir(&activations).map_err(|source| io_error(&activations, source))? {
            let entry = entry.map_err(|source| io_error(&activations, source))?;
            if !entry
                .file_type()
                .map_err(|source| io_error(entry.path(), source))?
                .is_dir()
            {
                continue;
            }
            let directory = entry.path();
            if !directory.join("image.json").is_file() {
                report.stale_mounts += usize::from(self.cleanup_activation(&directory)?);
                report.stale_staging_directories += 1;
            }
        }
        Ok(report)
    }

    fn prepare(
        &self,
        image: &LockedImage,
        credential: Option<&RegistryCredential>,
    ) -> Result<(PreparationStatus, ImmutableRootfs), SandboxError> {
        let status = self.pull(image, credential)?;
        let activated = self.activate(image)?;
        let rootfs = self.mount(&activated)?;
        Ok((status, rootfs))
    }
}

fn load_fixed_image(path: &Path) -> Result<LockedImage, SandboxError> {
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    let lock: TopologyLock = serde_json::from_slice(&bytes).map_err(|error| {
        SandboxError::ImageProvider(format!(
            "decode fixed-rootfs topology lock `{}`: {error}",
            path.display()
        ))
    })?;
    verify_lock(&lock)?;
    let mut images = lock.services.values().map(|service| &service.image);
    let image = images.next().ok_or_else(|| {
        SandboxError::ImageProvider(
            "fixed-rootfs topology lock must contain at least one service".to_owned(),
        )
    })?;
    if images.any(|candidate| candidate != image) {
        return Err(SandboxError::ImageProvider(
            "fixed-rootfs topology lock must bind exactly one image".to_owned(),
        ));
    }
    Ok(image.clone())
}

struct ImageReference<'a> {
    registry: &'a str,
    repository: &'a str,
}

fn parse_reference(value: &str) -> Result<ImageReference<'_>, SandboxError> {
    if value.is_empty()
        || value.len() > 4_096
        || value.starts_with('-')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
    {
        return Err(SandboxError::ImageProvider(
            "OCI image reference is invalid".to_owned(),
        ));
    }
    let (name, digest) = value
        .split_once('@')
        .map_or((value, None), |(name, digest)| (name, Some(digest)));
    if digest.is_some_and(|digest| !valid_digest(digest)) {
        return Err(SandboxError::ImageProvider(
            "OCI image reference digest is invalid".to_owned(),
        ));
    }
    let slash = name.find('/').ok_or_else(|| {
        SandboxError::ImageProvider(
            "OCI image reference must include an explicit registry".to_owned(),
        )
    })?;
    let registry = &name[..slash];
    let tagged_repository = &name[slash + 1..];
    let repository = tagged_repository
        .rfind(':')
        .map_or(tagged_repository, |colon| &tagged_repository[..colon]);
    let valid_registry = !registry.is_empty()
        && (registry.contains('.') || registry.contains(':') || registry == "localhost")
        && registry
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'_'));
    let valid_repository = !repository.is_empty()
        && repository.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        });
    if !valid_registry || !valid_repository {
        return Err(SandboxError::ImageProvider(
            "OCI registry or repository is invalid".to_owned(),
        ));
    }
    let repository_end = slash + 1 + repository.len();
    Ok(ImageReference {
        registry,
        repository: &name[..repository_end],
    })
}

fn image_record(source: &str, output: &[u8]) -> Result<(String, String), SandboxError> {
    let records = String::from_utf8_lossy(output)
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 3 && fields[0] == source)
                .then(|| (fields[1].to_owned(), fields[2].to_owned()))
        })
        .collect::<Vec<_>>();
    if records.len() != 1 || !valid_digest(&records[0].1) {
        return Err(SandboxError::ImageProvider(
            "containerd did not publish one resolved image record".to_owned(),
        ));
    }
    Ok(records[0].clone())
}

fn is_index_media_type(value: &str) -> bool {
    INDEX_MEDIA_TYPES.contains(&value)
}

fn is_manifest_media_type(value: &str) -> bool {
    MANIFEST_MEDIA_TYPES.contains(&value)
}

fn string_field(value: &Value, field: &str) -> Result<String, SandboxError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .map(str::to_owned)
        .ok_or_else(|| SandboxError::ImageProvider(format!("OCI metadata omits valid `{field}`")))
}

fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, SandboxError> {
    value
        .get(field)
        .ok_or_else(|| SandboxError::ImageProvider(format!("OCI metadata omits `{field}`")))
}

fn metadata_value(
    kind: &str,
    bytes: &[u8],
    expected_media_type: &str,
) -> Result<Value, SandboxError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        SandboxError::ImageProvider(format!("decode verified OCI {kind}: {error}"))
    })?;
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(2)
        || string_field(&value, "mediaType")? != expected_media_type
    {
        return Err(SandboxError::ImageProvider(format!(
            "OCI {kind} schema or media type is invalid"
        )));
    }
    Ok(value)
}

fn json_descriptor(value: &Value) -> Result<LockedDescriptor, SandboxError> {
    if value
        .get("urls")
        .and_then(Value::as_array)
        .is_some_and(|urls| !urls.is_empty())
    {
        return Err(SandboxError::ImageProvider(
            "OCI descriptor contains external URLs".to_owned(),
        ));
    }
    Ok(LockedDescriptor {
        media_type: string_field(value, "mediaType")?,
        digest: string_field(value, "digest")?,
        size: required_field(value, "size")?.as_u64().ok_or_else(|| {
            SandboxError::ImageProvider("OCI descriptor size is invalid".to_owned())
        })?,
    })
}

fn platform_matches(value: &Value, expected: &ImagePlatform) -> bool {
    let Some(platform) = value.get("platform") else {
        return false;
    };
    platform.get("os").and_then(Value::as_str) == Some(expected.operating_system.as_str())
        && platform.get("architecture").and_then(Value::as_str)
            == Some(expected.architecture.as_str())
        && platform.get("variant").and_then(Value::as_str) == expected.variant.as_deref()
}

fn digest_key(digest: &str) -> Result<String, SandboxError> {
    let value = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| SandboxError::ImageProvider("activation digest is not sha256".to_owned()))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SandboxError::ImageProvider(
            "activation digest is malformed".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn containerd_reference(image: &LockedImage) -> Result<String, SandboxError> {
    image.exact_reference.rsplit_once('@').ok_or_else(|| {
        SandboxError::ImageProvider("locked image reference is not pinned".to_owned())
    })?;
    Ok(image.exact_reference.clone())
}

fn remount_read_only(target: &Path) -> Result<(), SandboxError> {
    nix::mount::mount::<Path, Path, str, str>(
        None,
        target,
        None,
        nix::mount::MsFlags::MS_REMOUNT
            | nix::mount::MsFlags::MS_BIND
            | nix::mount::MsFlags::MS_RDONLY,
        None,
    )
    .map_err(|error| {
        SandboxError::ImageProvider(format!(
            "remount immutable rootfs `{}` read-only: {error}",
            target.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_fully_qualified_and_path_safe() {
        let tagged = parse_reference("registry.example:5000/team/app:stable").unwrap();
        assert_eq!(tagged.registry, "registry.example:5000");
        assert_eq!(tagged.repository, "registry.example:5000/team/app");

        let pinned_value = format!("docker.io/library/alpine@sha256:{}", "a".repeat(64));
        let pinned = parse_reference(&pinned_value).unwrap();
        assert_eq!(pinned.repository, "docker.io/library/alpine");
        assert!(parse_reference("alpine:latest").is_err());
        assert!(parse_reference("docker.io/../host:latest").is_err());
        assert!(parse_reference("docker.io/library/alpine@sha256:bad").is_err());
    }

    #[test]
    fn image_records_require_one_exact_digest_result() {
        let output = format!(
            "REF TYPE DIGEST SIZE PLATFORMS LABELS\n\
             docker.io/library/alpine:3.20 application/vnd.oci.image.index.v1+json sha256:{} 1KiB linux/amd64 -\n",
            "b".repeat(64)
        );
        let (media_type, digest) =
            image_record("docker.io/library/alpine:3.20", output.as_bytes()).unwrap();
        assert_eq!(media_type, "application/vnd.oci.image.index.v1+json");
        assert_eq!(digest, format!("sha256:{}", "b".repeat(64)));
        assert!(image_record("docker.io/library/missing:latest", output.as_bytes()).is_err());
    }
}
