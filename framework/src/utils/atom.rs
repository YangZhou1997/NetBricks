use arc_swap::{ArcSwap, Lease};
use std::sync::Arc;

/// Wrapper for static settings/config around ArcCell
pub struct Atom<T>
where
    T: 'static,
{
    data: ArcSwap<T>,
}

impl<T> Atom<T> {
    pub fn new(d: T) -> Self {
        Atom {
            data: ArcSwap::new(Arc::new(d)),
        }
    }

    pub fn get(&self) -> Arc<T> {
        self.data.load()
    }

    pub fn borrow(&self) -> Lease<Arc<T>> {
        self.data.lease()
    }

    pub fn set(&self, d: T) {
        self.data.store(Arc::new(d))
    }

    pub fn swap(&self, d: T) -> Arc<T> {
        self.data.swap(Arc::new(d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap() {
        let config = Atom::new(String::default());
        let new_config = config.swap("New Config".to_owned());
        assert_eq!(*new_config, "");
        assert_eq!(*config.get(), "New Config");
    }

    #[test]
    fn get() {
        let config = Atom::new(String::default());
        assert_eq!(*config.get(), "");
    }

    #[test]
    fn set() {
        let config = Atom::new(String::default());
        config.set("New Config".to_owned());
        assert_eq!(*config.get(), "New Config");
    }

    #[test]
    fn borrow() {
        let config = Atom::new(String::default());
        config.set("New Config".to_owned());
        assert_eq!(*config.borrow(), "New Config");
    }
}
