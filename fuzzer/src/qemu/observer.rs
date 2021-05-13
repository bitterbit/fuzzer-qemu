use serde::{Deserialize, Serialize};

use libafl::{bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider}, executors::HasExecHooks};
use libafl::{
    bolts::{ownedref::OwnedArrayPtrMut, tuples::Named},
    observers::{MapObserver, Observer},
    Error,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct SharedMemObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: OwnedArrayPtrMut<T>,
    initial: T,
    name: String,
}

impl<T> Observer for SharedMemObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
}


impl<EM, I, S, T, Z> HasExecHooks<EM, I, S, Z> for SharedMemObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    Self: MapObserver<T>,
{
    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        self.reset_map()
    }
}

impl<T> Named for SharedMemObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapObserver<T> for SharedMemObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn map(&self) -> &[T] {
        self.map.as_slice()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    #[inline]
    fn set_initial(&mut self, initial: T) {
        self.initial = initial
    }
}

impl<T> SharedMemObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new MapObserver
    pub fn new(name: &'static str, env_shmem_key: &str, map_size: usize) -> Self {
        let mut shmem = StdShMemProvider::new()
            .unwrap()
            .new_map(map_size)
            .expect("Error creating shared memory");

        assert!(shmem.len() <= map_size);
        shmem
            .write_to_env(env_shmem_key)
            .expect("Error while exporting shared memory to environment variable");

        let ptr: *mut T = shmem.map_mut().as_mut_ptr() as *mut T;

        Self {
            name: name.to_string(),
            map: OwnedArrayPtrMut::ArrayPtr((ptr, shmem.len())),
            initial: unsafe { *ptr },
        }
    }
}
