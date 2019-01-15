
/*
use std::result::Result;

pub trait AdvanceIter {
    type Error;

    fn advance(&mut self) -> Result<(), Self::Error>;

    //fn advance(&mut self) -> Result<(), Self::Error>;
    //fn get(self) -> Option<Self::Item>;

    /*
    fn next(self) -> Result<Option<Self::Item>, Self::Error> {
        self.advance()?;
        Ok(self.get())
    }
    */

    //fn next(self) -> Result<Option<Self::Item>, Self::Error>;
}

pub trait GetIter {
    type Item;

    fn get(self) -> Option<Self::Item>;
}

#[derive(Clone)]
pub struct Filter<I, P> {
    iter: I,
    predicate: P,
}

impl<'a, I:'a, P> Filter<I, P>
    where &'a I: GetIter
{
    fn get_inner(&'a self) -> Option<<&'a I as GetIter>::Item> {
        let i = &self.iter;
        i.get()
    }
}

impl<'a, I:'a, P> AdvanceIter for Filter<I, P> 
    where
        I: AdvanceIter,
        &'a I: GetIter,
        P: Fn(<&'a I as GetIter>::Item) -> bool
{
    type Error = I::Error;
    fn advance(&mut self) -> Result<(), Self::Error> {
        loop {
            self.iter.advance()?;
            if let Some(r) = self.get_inner() {
                if (self.predicate)(r) {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
    }
}

/*
impl<'a, I, P> GetIter for &'a Filter<I, P> 
    where &'a I: GetIter
{
    type Item = <&'a I as GetIter>::Item;

    fn get(self) -> Option<Self::Item> {
        self.iter.get()
    }
}
*/

/*
impl<'a, I, P> Iter for &'a mut Filter<I, P>
    where &'a mut I: Iter,
    P: FnMut(<&'a mut I as Iter>::Item) -> bool
{
    type Item = <&'a mut I as Iter>::Item;
    type Error = <&'a mut I as Iter>::Error;

    fn next(self) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            if let Some(r) = self.iter.next()? {
                if (self.predicate)(r) {
                    return Ok(Some(r));
                }
            } else {
                return Ok(None);
            }
        }
    }

    fn advance(&mut self) -> Result<(), Self::Error> {
        loop {
            self.iter.advance()?;
            {
                let i = &self.iter;
                if let Some(r) = i.get() {
                    if (self.predicate)(r) {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            }
        }
    }

    fn get(self) -> Option<Self::Item> {
        self.iter.get()
    }
}
    */

#[cfg(test)]
mod test {
    use hamcrest2::prelude::*;
    use super::AdvanceIter;
    use super::GetIter;

    struct Foo {
        idx: Option<usize>,
        size: usize,
        slice: &'static [u8],
    }

    impl Foo {
        fn next(&mut self) -> Result<Option<&[u8]>, ()> {
            self.advance()?;
            Ok(self.get())
        }
    }

    impl AdvanceIter for Foo {
        type Error = ();

        fn advance(&mut self) -> Result<(), Self::Error> {
            self.idx = match self.idx {
                None => Some(0),
                Some(i) => Some(i + self.size),
            };
            Ok(())
        }
    }

    impl<'a> GetIter for &'a Foo {
        type Item = &'a [u8];

        fn get(self) -> Option<Self::Item> {
            let start = self.idx.unwrap();
            if start >= self.slice.len() {
                None
            } else {
                Some(&self.slice[start..start+self.size])
            }
        }
    }

        /*

    impl<'a> Iter for &'a mut Foo {
        type Item = &'a [u8];
        type Error = ();

        fn next(self) -> Result<Option<Self::Item>, Self::Error> {
            self.idx = match self.idx {
                None => Some(0),
                Some(i) => Some(i + self.size),
            };
            let start = self.idx.unwrap();
            Ok(
                if start >= self.slice.len() {
                    None
                } else {
                    Some(&self.slice[start..start+self.size])
                }
            )
        }

        fn advance(&mut self) -> Result<(), Self::Error> {
            self.idx = match self.idx {
                None => Some(0),
                Some(i) => Some(i + self.size),
            };
            Ok(())
        }
    
        fn get(&'a self) -> Option<Self::Item> {
            let start = self.idx.unwrap();
            if start >= self.slice.len() {
                None
            } else {
                Some(&self.slice[start..start+self.size])
            }
        }
    }
        */

    #[test]
    fn simple_iter() {
        let mut foo = Foo{
            idx: None,
            size: 2,
            slice: b"aabbccddee",
        };
        assert_that!(foo.next().unwrap().unwrap(), eq(b"aa"));
        assert_that!(foo.next().unwrap().unwrap(), eq(b"bb"));
        assert_that!(foo.next().unwrap().unwrap(), eq(b"cc"));
        assert_that!(foo.next().unwrap().unwrap(), eq(b"dd"));
        assert_that!(foo.next().unwrap().unwrap(), eq(b"ee"));
        assert_that!(foo.next().unwrap(), none());
    }
}
*/
