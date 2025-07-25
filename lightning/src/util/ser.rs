// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as [`ChannelManager`]s and [`ChannelMonitor`]s.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor

use crate::io::{self, BufRead, Read, Write};
use crate::io_extras::{copy, sink};
use crate::ln::interactivetxs::{InteractiveTxOutput, NegotiatedTxInput};
use crate::ln::onion_utils::{HMAC_COUNT, HMAC_LEN, HOLD_TIME_LEN, MAX_HOPS};
use crate::prelude::*;
use crate::sync::{Mutex, RwLock};
use core::cmp;
use core::hash::Hash;
use core::ops::Deref;

use alloc::collections::BTreeMap;

use bitcoin::absolute::LockTime as AbsoluteLockTime;
use bitcoin::amount::Amount;
use bitcoin::consensus::Encodable;
use bitcoin::constants::ChainHash;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::hmac::Hmac;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::script::{self, ScriptBuf};
use bitcoin::secp256k1::constants::{
	COMPACT_SIGNATURE_SIZE, PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE,
};
use bitcoin::secp256k1::ecdsa;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::transaction::{OutPoint, Transaction, TxOut};
use bitcoin::{consensus, TxIn, Weight, Witness};

use dnssec_prover::rr::Name;

use crate::chain::ClaimId;
#[cfg(taproot)]
use crate::ln::msgs::PartialSignatureWithNonce;
use crate::ln::msgs::{DecodeError, SerialId};
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::types::string::UntrustedString;
use crate::util::byte_utils::{be48_to_array, slice_to_be48};

use core::time::Duration;

/// serialization buffer size
pub const MAX_BUF_SIZE: usize = 64 * 1024;

/// A simplified version of `std::io::Write` that exists largely for backwards compatibility.
/// An impl is provided for any type that also impls `std::io::Write`.
///
/// This is not exported to bindings users as we only export serialization to/from byte arrays instead
pub trait Writer {
	/// Writes the given buf out. See std::io::Write::write_all for more
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error>;
}

impl<W: Write> Writer for W {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		<Self as io::Write>::write_all(self, buf)
	}
}

// TODO: Drop this entirely if rust-bitcoin releases a version bump with https://github.com/rust-bitcoin/rust-bitcoin/pull/3173
/// Wrap buffering support for implementations of Read.
/// A [`Read`]er which keeps an internal buffer to avoid hitting the underlying stream directly for
/// every read, implementing [`BufRead`].
///
/// In order to avoid reading bytes past the first object, and those bytes then ending up getting
/// dropped, this BufReader operates in one-byte-increments.
struct BufReader<'a, R: Read> {
	inner: &'a mut R,
	buf: [u8; 1],
	is_consumed: bool,
}

impl<'a, R: Read> BufReader<'a, R> {
	/// Creates a [`BufReader`] which will read from the given `inner`.
	pub fn new(inner: &'a mut R) -> Self {
		BufReader { inner, buf: [0; 1], is_consumed: true }
	}
}

impl<'a, R: Read> Read for BufReader<'a, R> {
	#[inline]
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let mut offset = 0;
		if !self.is_consumed {
			output[0] = self.buf[0];
			self.is_consumed = true;
			offset = 1;
		}
		self.inner.read(&mut output[offset..]).map(|len| len + offset)
	}
}

impl<'a, R: Read> BufRead for BufReader<'a, R> {
	#[inline]
	fn fill_buf(&mut self) -> io::Result<&[u8]> {
		debug_assert!(false, "rust-bitcoin doesn't actually use this");
		if self.is_consumed {
			let count = self.inner.read(&mut self.buf[..])?;
			debug_assert!(count <= 1, "read gave us a garbage length");

			// upon hitting EOF, assume the byte is already consumed
			self.is_consumed = count == 0;
		}

		if self.is_consumed {
			Ok(&[])
		} else {
			Ok(&self.buf[..])
		}
	}

	#[inline]
	fn consume(&mut self, amount: usize) {
		debug_assert!(false, "rust-bitcoin doesn't actually use this");
		if amount >= 1 {
			debug_assert_eq!(amount, 1, "Can only consume one byte");
			debug_assert!(!self.is_consumed, "Cannot consume more than had been read");
			self.is_consumed = true;
		}
	}
}

pub(crate) struct WriterWriteAdaptor<'a, W: Writer + 'a>(pub &'a mut W);
impl<'a, W: Writer + 'a> Write for WriterWriteAdaptor<'a, W> {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0.write_all(buf)
	}
	#[inline]
	fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
		self.0.write_all(buf)?;
		Ok(buf.len())
	}
	#[inline]
	fn flush(&mut self) -> Result<(), io::Error> {
		Ok(())
	}
}

pub(crate) struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

/// Writer that only tracks the amount of data written - useful if you need to calculate the length
/// of some data when serialized but don't yet need the full data.
///
/// This is not exported to bindings users as manual TLV building is not currently supported in bindings
pub struct LengthCalculatingWriter(pub usize);
impl Writer for LengthCalculatingWriter {
	#[inline]
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0 += buf.len();
		Ok(())
	}
}

/// Essentially `std::io::Take` but a bit simpler and with a method to walk the underlying stream
/// forward to ensure we always consume exactly the fixed length specified.
///
/// This is not exported to bindings users as manual TLV building is not currently supported in bindings
pub struct FixedLengthReader<'a, R: Read> {
	read: &'a mut R,
	bytes_read: u64,
	total_bytes: u64,
}
impl<'a, R: Read> FixedLengthReader<'a, R> {
	/// Returns a new [`FixedLengthReader`].
	pub fn new(read: &'a mut R, total_bytes: u64) -> Self {
		Self { read, bytes_read: 0, total_bytes }
	}

	/// Returns whether some bytes are remaining or not.
	#[inline]
	pub fn bytes_remain(&mut self) -> bool {
		self.bytes_read != self.total_bytes
	}

	/// Consumes the remaining bytes.
	#[inline]
	pub fn eat_remaining(&mut self) -> Result<(), DecodeError> {
		copy(self, &mut sink()).unwrap();
		if self.bytes_read != self.total_bytes {
			Err(DecodeError::ShortRead)
		} else {
			Ok(())
		}
	}
}
impl<'a, R: Read> Read for FixedLengthReader<'a, R> {
	#[inline]
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		if self.total_bytes == self.bytes_read {
			Ok(0)
		} else {
			let read_len = cmp::min(dest.len() as u64, self.total_bytes - self.bytes_read);
			match self.read.read(&mut dest[0..(read_len as usize)]) {
				Ok(v) => {
					self.bytes_read += v as u64;
					Ok(v)
				},
				Err(e) => Err(e),
			}
		}
	}
}

impl<'a, R: Read> LengthLimitedRead for FixedLengthReader<'a, R> {
	#[inline]
	fn remaining_bytes(&self) -> u64 {
		self.total_bytes.saturating_sub(self.bytes_read)
	}
}

/// A [`Read`] implementation which tracks whether any bytes have been read at all. This allows us to distinguish
/// between "EOF reached before we started" and "EOF reached mid-read".
///
/// This is not exported to bindings users as manual TLV building is not currently supported in bindings
pub struct ReadTrackingReader<'a, R: Read> {
	read: &'a mut R,
	/// Returns whether we have read from this reader or not yet.
	pub have_read: bool,
}
impl<'a, R: Read> ReadTrackingReader<'a, R> {
	/// Returns a new [`ReadTrackingReader`].
	pub fn new(read: &'a mut R) -> Self {
		Self { read, have_read: false }
	}
}
impl<'a, R: Read> Read for ReadTrackingReader<'a, R> {
	#[inline]
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		match self.read.read(dest) {
			Ok(0) => Ok(0),
			Ok(len) => {
				self.have_read = true;
				Ok(len)
			},
			Err(e) => Err(e),
		}
	}
}

/// A trait that various LDK types implement allowing them to be written out to a [`Writer`].
///
/// This is not exported to bindings users as we only export serialization to/from byte arrays instead
pub trait Writeable {
	/// Writes `self` out to the given [`Writer`].
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error>;

	/// Writes `self` out to a `Vec<u8>`.
	fn encode(&self) -> Vec<u8> {
		let len = self.serialized_length();
		let mut msg = VecWriter(Vec::with_capacity(len));
		self.write(&mut msg).unwrap();
		// Note that objects with interior mutability may change size between when we called
		// serialized_length and when we called write. That's okay, but shouldn't happen during
		// testing as most of our tests are not threaded.
		#[cfg(test)]
		debug_assert_eq!(len, msg.0.len());
		msg.0
	}

	/// Writes `self` out to a `Vec<u8>`.
	#[cfg(test)]
	fn encode_with_len(&self) -> Vec<u8> {
		let mut msg = VecWriter(Vec::new());
		0u16.write(&mut msg).unwrap();
		self.write(&mut msg).unwrap();
		let len = msg.0.len();
		debug_assert_eq!(len - 2, self.serialized_length());
		msg.0[..2].copy_from_slice(&(len as u16 - 2).to_be_bytes());
		msg.0
	}

	/// Gets the length of this object after it has been serialized. This can be overridden to
	/// optimize cases where we prepend an object with its length.
	// Note that LLVM optimizes this away in most cases! Check that it isn't before you override!
	#[inline]
	fn serialized_length(&self) -> usize {
		let mut len_calc = LengthCalculatingWriter(0);
		self.write(&mut len_calc).expect("No in-memory data may fail to serialize");
		len_calc.0
	}
}

impl<'a, T: Writeable> Writeable for &'a T {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		(*self).write(writer)
	}
}

/// A trait that various LDK types implement allowing them to be read in from a [`Read`].
///
/// This is not exported to bindings users as we only export serialization to/from byte arrays instead
pub trait Readable
where
	Self: Sized,
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError>;
}

/// A trait that various LDK types implement allowing them to be read in from a
/// [`io::Cursor`].
pub(crate) trait CursorReadable
where
	Self: Sized,
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: AsRef<[u8]>>(reader: &mut io::Cursor<R>) -> Result<Self, DecodeError>;
}

/// A trait that various higher-level LDK types implement allowing them to be read in
/// from a [`Read`] given some additional set of arguments which is required to deserialize.
///
/// This is not exported to bindings users as we only export serialization to/from byte arrays instead
pub trait ReadableArgs<P>
where
	Self: Sized,
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read>(reader: &mut R, params: P) -> Result<Self, DecodeError>;
}

/// A [`io::Read`] that limits the amount of bytes that can be read. Implementations should ensure
/// that the object being read will only consume a fixed number of bytes from the underlying
/// [`io::Read`], see [`FixedLengthReader`] for an example.
pub trait LengthLimitedRead: Read {
	/// The number of bytes remaining to be read.
	fn remaining_bytes(&self) -> u64;
}

impl LengthLimitedRead for &[u8] {
	fn remaining_bytes(&self) -> u64 {
		// The underlying `Read` implementation for slice updates the slice to point to the yet unread
		// part.
		self.len() as u64
	}
}

/// Similar to [`LengthReadable`]. Useful when an additional set of arguments is required to
/// deserialize.
pub(crate) trait LengthReadableArgs<P>
where
	Self: Sized,
{
	/// Reads a `Self` in from the given [`LengthLimitedRead`].
	fn read<R: LengthLimitedRead>(reader: &mut R, params: P) -> Result<Self, DecodeError>;
}

/// A trait that allows the implementer to be read in from a [`LengthLimitedRead`], requiring the
/// reader to limit the number of total bytes read from its underlying [`Read`]. Useful for structs
/// that will always consume the entire provided [`Read`] when deserializing.
///
/// Any type that implements [`Readable`] also automatically has a [`LengthReadable`]
/// implementation, but some types, most notably onion packets, only implement [`LengthReadable`].
pub trait LengthReadable
where
	Self: Sized,
{
	/// Reads a `Self` in from the given [`LengthLimitedRead`].
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(
		reader: &mut R,
	) -> Result<Self, DecodeError>;
}

impl<T: Readable> LengthReadable for T {
	#[inline]
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(
		reader: &mut R,
	) -> Result<T, DecodeError> {
		Readable::read(reader)
	}
}

/// A trait that various LDK types implement allowing them to (maybe) be read in from a [`Read`].
///
/// This is not exported to bindings users as we only export serialization to/from byte arrays instead
pub trait MaybeReadable
where
	Self: Sized,
{
	/// Reads a `Self` in from the given [`Read`].
	fn read<R: Read>(reader: &mut R) -> Result<Option<Self>, DecodeError>;
}

impl<T: Readable> MaybeReadable for T {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<Option<T>, DecodeError> {
		Ok(Some(Readable::read(reader)?))
	}
}

/// Wrapper to read a required (non-optional) TLV record.
///
/// This is not exported to bindings users as manual TLV building is not currently supported in bindings
pub struct RequiredWrapper<T>(pub Option<T>);
impl<T: LengthReadable> LengthReadable for RequiredWrapper<T> {
	#[inline]
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(
		reader: &mut R,
	) -> Result<Self, DecodeError> {
		Ok(Self(Some(LengthReadable::read_from_fixed_length_buffer(reader)?)))
	}
}
impl<A, T: ReadableArgs<A>> ReadableArgs<A> for RequiredWrapper<T> {
	#[inline]
	fn read<R: Read>(reader: &mut R, args: A) -> Result<Self, DecodeError> {
		Ok(Self(Some(ReadableArgs::read(reader, args)?)))
	}
}
/// When handling `default_values`, we want to map the default-value T directly
/// to a `RequiredWrapper<T>` in a way that works for `field: T = t;` as
/// well. Thus, we assume `Into<T> for T` does nothing and use that.
impl<T> From<T> for RequiredWrapper<T> {
	fn from(t: T) -> RequiredWrapper<T> {
		RequiredWrapper(Some(t))
	}
}
impl<T: Clone> Clone for RequiredWrapper<T> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}
impl<T: Copy> Copy for RequiredWrapper<T> {}

/// Wrapper to read a required (non-optional) TLV record that may have been upgraded without
/// backwards compat.
///
/// This is not exported to bindings users as manual TLV building is not currently supported in bindings
pub struct UpgradableRequired<T: MaybeReadable>(pub Option<T>);
impl<T: MaybeReadable> MaybeReadable for UpgradableRequired<T> {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		let tlv = MaybeReadable::read(reader)?;
		if let Some(tlv) = tlv {
			return Ok(Some(Self(Some(tlv))));
		}
		Ok(None)
	}
}

pub(crate) struct U48(pub u64);
impl Writeable for U48 {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&be48_to_array(self.0))
	}
}
impl Readable for U48 {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<U48, DecodeError> {
		let mut buf = [0; 6];
		reader.read_exact(&mut buf)?;
		Ok(U48(slice_to_be48(&buf)))
	}
}

/// Lightning TLV uses a custom variable-length integer called `BigSize`. It is similar to Bitcoin's
/// variable-length integers except that it is serialized in big-endian instead of little-endian.
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that certain values can be
/// encoded in several different ways, which we must check for at deserialization-time. Thus, if
/// you're looking for an example of a variable-length integer to use for your own project, move
/// along, this is a rather poor design.
#[derive(Clone, Copy, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct BigSize(pub u64);
impl Writeable for BigSize {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self.0 {
			0..=0xFC => (self.0 as u8).write(writer),
			0xFD..=0xFFFF => {
				0xFDu8.write(writer)?;
				(self.0 as u16).write(writer)
			},
			0x10000..=0xFFFFFFFF => {
				0xFEu8.write(writer)?;
				(self.0 as u32).write(writer)
			},
			_ => {
				0xFFu8.write(writer)?;
				(self.0 as u64).write(writer)
			},
		}
	}
}
impl Readable for BigSize {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<BigSize, DecodeError> {
		let n: u8 = Readable::read(reader)?;
		match n {
			0xFF => {
				let x: u64 = Readable::read(reader)?;
				if x < 0x100000000 {
					Err(DecodeError::InvalidValue)
				} else {
					Ok(BigSize(x))
				}
			},
			0xFE => {
				let x: u32 = Readable::read(reader)?;
				if x < 0x10000 {
					Err(DecodeError::InvalidValue)
				} else {
					Ok(BigSize(x as u64))
				}
			},
			0xFD => {
				let x: u16 = Readable::read(reader)?;
				if x < 0xFD {
					Err(DecodeError::InvalidValue)
				} else {
					Ok(BigSize(x as u64))
				}
			},
			n => Ok(BigSize(n as u64)),
		}
	}
}

/// The lightning protocol uses u16s for lengths in most cases. As our serialization framework
/// primarily targets that, we must as well. However, because we may serialize objects that have
/// more than 65K entries, we need to be able to store larger values. Thus, we define a variable
/// length integer here that is backwards-compatible for values < 0xffff. We treat 0xffff as
/// "read eight more bytes".
///
/// To ensure we only have one valid encoding per value, we add 0xffff to values written as eight
/// bytes. Thus, 0xfffe is serialized as 0xfffe, whereas 0xffff is serialized as
/// 0xffff0000000000000000 (i.e. read-eight-bytes then zero).
struct CollectionLength(pub u64);
impl Writeable for CollectionLength {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		if self.0 < 0xffff {
			(self.0 as u16).write(writer)
		} else {
			0xffffu16.write(writer)?;
			(self.0 - 0xffff).write(writer)
		}
	}
}

impl Readable for CollectionLength {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut val: u64 = <u16 as Readable>::read(r)? as u64;
		if val == 0xffff {
			val =
				<u64 as Readable>::read(r)?.checked_add(0xffff).ok_or(DecodeError::InvalidValue)?;
		}
		Ok(CollectionLength(val))
	}
}

/// In TLV we occasionally send fields which only consist of, or potentially end with, a
/// variable-length integer which is simply truncated by skipping high zero bytes. This type
/// encapsulates such integers implementing [`Readable`]/[`Writeable`] for them.
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub(crate) struct HighZeroBytesDroppedBigSize<T>(pub T);

macro_rules! impl_writeable_primitive {
	($val_type:ty, $len: expr) => {
		impl Writeable for $val_type {
			#[inline]
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
				writer.write_all(&self.to_be_bytes())
			}
		}
		impl Writeable for HighZeroBytesDroppedBigSize<$val_type> {
			#[inline]
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
				// Skip any full leading 0 bytes when writing (in BE):
				writer.write_all(&self.0.to_be_bytes()[(self.0.leading_zeros() / 8) as usize..$len])
			}
		}
		impl Readable for $val_type {
			#[inline]
			fn read<R: Read>(reader: &mut R) -> Result<$val_type, DecodeError> {
				let mut buf = [0; $len];
				reader.read_exact(&mut buf)?;
				Ok(<$val_type>::from_be_bytes(buf))
			}
		}
		impl Readable for HighZeroBytesDroppedBigSize<$val_type> {
			#[inline]
			fn read<R: Read>(
				reader: &mut R,
			) -> Result<HighZeroBytesDroppedBigSize<$val_type>, DecodeError> {
				// We need to accept short reads (read_len == 0) as "EOF" and handle them as simply
				// the high bytes being dropped. To do so, we start reading into the middle of buf
				// and then convert the appropriate number of bytes with extra high bytes out of
				// buf.
				let mut buf = [0; $len * 2];
				let mut read_len = reader.read(&mut buf[$len..])?;
				let mut total_read_len = read_len;
				while read_len != 0 && total_read_len != $len {
					read_len = reader.read(&mut buf[($len + total_read_len)..])?;
					total_read_len += read_len;
				}
				if total_read_len == 0 || buf[$len] != 0 {
					let first_byte = $len - ($len - total_read_len);
					let mut bytes = [0; $len];
					bytes.copy_from_slice(&buf[first_byte..first_byte + $len]);
					Ok(HighZeroBytesDroppedBigSize(<$val_type>::from_be_bytes(bytes)))
				} else {
					// If the encoding had extra zero bytes, return a failure even though we know
					// what they meant (as the TLV test vectors require this)
					Err(DecodeError::InvalidValue)
				}
			}
		}
		impl From<$val_type> for HighZeroBytesDroppedBigSize<$val_type> {
			fn from(val: $val_type) -> Self {
				Self(val)
			}
		}
	};
}

impl_writeable_primitive!(u128, 16);
impl_writeable_primitive!(u64, 8);
impl_writeable_primitive!(u32, 4);
impl_writeable_primitive!(u16, 2);
impl_writeable_primitive!(i64, 8);
impl_writeable_primitive!(i32, 4);
impl_writeable_primitive!(i16, 2);
impl_writeable_primitive!(i8, 1);

impl Writeable for u8 {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&[*self])
	}
}
impl Readable for u8 {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<u8, DecodeError> {
		let mut buf = [0; 1];
		reader.read_exact(&mut buf)?;
		Ok(buf[0])
	}
}

impl Writeable for bool {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&[if *self { 1 } else { 0 }])
	}
}
impl Readable for bool {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<bool, DecodeError> {
		let mut buf = [0; 1];
		reader.read_exact(&mut buf)?;
		if buf[0] != 0 && buf[0] != 1 {
			return Err(DecodeError::InvalidValue);
		}
		Ok(buf[0] == 1)
	}
}

macro_rules! impl_array {
	($size:expr, $ty: ty) => {
		impl Writeable for [$ty; $size] {
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				let mut out = [0; $size * core::mem::size_of::<$ty>()];
				for (idx, v) in self.iter().enumerate() {
					let startpos = idx * core::mem::size_of::<$ty>();
					out[startpos..startpos + core::mem::size_of::<$ty>()]
						.copy_from_slice(&v.to_be_bytes());
				}
				w.write_all(&out)
			}
		}

		impl Readable for [$ty; $size] {
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let mut buf = [0u8; $size * core::mem::size_of::<$ty>()];
				r.read_exact(&mut buf)?;
				let mut res = [0; $size];
				for (idx, v) in res.iter_mut().enumerate() {
					let startpos = idx * core::mem::size_of::<$ty>();
					let mut arr = [0; core::mem::size_of::<$ty>()];
					arr.copy_from_slice(&buf[startpos..startpos + core::mem::size_of::<$ty>()]);
					*v = <$ty>::from_be_bytes(arr);
				}
				Ok(res)
			}
		}
	};
}

impl_array!(3, u8); // for rgb, ISO 4217 code
impl_array!(4, u8); // for IPv4
impl_array!(12, u8); // for OnionV2
impl_array!(16, u8); // for IPv6
impl_array!(32, u8); // for channel id & hmac
impl_array!(PUBLIC_KEY_SIZE, u8); // for PublicKey
impl_array!(64, u8); // for ecdsa::Signature and schnorr::Signature
impl_array!(66, u8); // for MuSig2 nonces
impl_array!(1300, u8); // for OnionPacket.hop_data

impl_array!(8, u16);
impl_array!(32, u16);

// Implement array serialization for attribution_data.
impl_array!(MAX_HOPS * HOLD_TIME_LEN, u8);
impl_array!(HMAC_LEN * HMAC_COUNT, u8);

/// A type for variable-length values within TLV record where the length is encoded as part of the record.
/// Used to prevent encoding the length twice.
///
/// This is not exported to bindings users as manual TLV building is not currently supported in bindings
pub struct WithoutLength<T>(pub T);

impl Writeable for WithoutLength<&String> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(self.0.as_bytes())
	}
}
impl LengthReadable for WithoutLength<String> {
	#[inline]
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let v: WithoutLength<Vec<u8>> = LengthReadable::read_from_fixed_length_buffer(r)?;
		Ok(Self(String::from_utf8(v.0).map_err(|_| DecodeError::InvalidValue)?))
	}
}
impl<'a> From<&'a String> for WithoutLength<&'a String> {
	fn from(s: &'a String) -> Self {
		Self(s)
	}
}

impl Writeable for UntrustedString {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for UntrustedString {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let s: String = Readable::read(r)?;
		Ok(Self(s))
	}
}

impl Writeable for WithoutLength<&UntrustedString> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.0 .0).write(w)
	}
}
impl LengthReadable for WithoutLength<UntrustedString> {
	#[inline]
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let s: WithoutLength<String> = LengthReadable::read_from_fixed_length_buffer(r)?;
		Ok(Self(UntrustedString(s.0)))
	}
}

trait AsWriteableSlice {
	type Inner: Writeable;
	fn as_slice(&self) -> &[Self::Inner];
}

impl<T: Writeable> AsWriteableSlice for &Vec<T> {
	type Inner = T;
	fn as_slice(&self) -> &[T] {
		&self
	}
}
impl<T: Writeable> AsWriteableSlice for &[T] {
	type Inner = T;
	fn as_slice(&self) -> &[T] {
		&self
	}
}

impl<S: AsWriteableSlice> Writeable for WithoutLength<S> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for ref v in self.0.as_slice() {
			v.write(writer)?;
		}
		Ok(())
	}
}

impl<T: MaybeReadable> LengthReadable for WithoutLength<Vec<T>> {
	#[inline]
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(
		reader: &mut R,
	) -> Result<Self, DecodeError> {
		let mut values = Vec::new();
		loop {
			let mut track_read = ReadTrackingReader::new(reader);
			match MaybeReadable::read(&mut track_read) {
				Ok(Some(v)) => {
					values.push(v);
				},
				Ok(None) => {},
				// If we failed to read any bytes at all, we reached the end of our TLV
				// stream and have simply exhausted all entries.
				Err(ref e) if e == &DecodeError::ShortRead && !track_read.have_read => break,
				Err(e) => return Err(e),
			}
		}
		Ok(Self(values))
	}
}
impl<'a, T> From<&'a Vec<T>> for WithoutLength<&'a Vec<T>> {
	fn from(v: &'a Vec<T>) -> Self {
		Self(v)
	}
}

impl Writeable for WithoutLength<&ScriptBuf> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(self.0.as_bytes())
	}
}

impl LengthReadable for WithoutLength<ScriptBuf> {
	#[inline]
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let v: WithoutLength<Vec<u8>> = LengthReadable::read_from_fixed_length_buffer(r)?;
		Ok(WithoutLength(script::Builder::from(v.0).into_script()))
	}
}

#[derive(Debug)]
pub(crate) struct Iterable<'a, I: Iterator<Item = &'a T> + Clone, T: 'a>(pub I);

impl<'a, I: Iterator<Item = &'a T> + Clone, T: 'a + Writeable> Writeable for Iterable<'a, I, T> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for ref v in self.0.clone() {
			v.write(writer)?;
		}
		Ok(())
	}
}

#[cfg(test)]
impl<'a, I: Iterator<Item = &'a T> + Clone, T: 'a + PartialEq> PartialEq for Iterable<'a, I, T> {
	fn eq(&self, other: &Self) -> bool {
		self.0.clone().collect::<Vec<_>>() == other.0.clone().collect::<Vec<_>>()
	}
}

#[derive(Debug)]
pub(crate) struct IterableOwned<I: Iterator<Item = T> + Clone, T>(pub I);

impl<I: Iterator<Item = T> + Clone, T: Writeable> Writeable for IterableOwned<I, T> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for ref v in self.0.clone() {
			v.write(writer)?;
		}
		Ok(())
	}
}

macro_rules! impl_for_map {
	($ty: ident, $keybound: ident, $constr: expr) => {
		impl<K, V> Writeable for $ty<K, V>
		where
			K: Writeable + Eq + $keybound,
			V: Writeable,
		{
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				CollectionLength(self.len() as u64).write(w)?;
				for (key, value) in self.iter() {
					key.write(w)?;
					value.write(w)?;
				}
				Ok(())
			}
		}

		impl<K, V> Readable for $ty<K, V>
		where
			K: Readable + Eq + $keybound,
			V: MaybeReadable,
		{
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let len: CollectionLength = Readable::read(r)?;
				let mut ret = $constr(len.0 as usize);
				for _ in 0..len.0 {
					let k = K::read(r)?;
					let v_opt = V::read(r)?;
					if let Some(v) = v_opt {
						if ret.insert(k, v).is_some() {
							return Err(DecodeError::InvalidValue);
						}
					}
				}
				Ok(ret)
			}
		}
	};
}

impl_for_map!(BTreeMap, Ord, |_| BTreeMap::new());
impl_for_map!(HashMap, Hash, |len| hash_map_with_capacity(len));

// HashSet
impl<T> Writeable for HashSet<T>
where
	T: Writeable + Eq + Hash,
{
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.len() as u64).write(w)?;
		for item in self.iter() {
			item.write(w)?;
		}
		Ok(())
	}
}

impl<T> Readable for HashSet<T>
where
	T: Readable + Eq + Hash,
{
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: CollectionLength = Readable::read(r)?;
		let mut ret = hash_set_with_capacity(cmp::min(
			len.0 as usize,
			MAX_BUF_SIZE / core::mem::size_of::<T>(),
		));
		for _ in 0..len.0 {
			if !ret.insert(T::read(r)?) {
				return Err(DecodeError::InvalidValue);
			}
		}
		Ok(ret)
	}
}

// Vectors
macro_rules! impl_writeable_for_vec {
	($ty: ty $(, $name: ident)*) => {
		impl<$($name : Writeable),*> Writeable for Vec<$ty> {
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				CollectionLength(self.len() as u64).write(w)?;
				for elem in self.iter() {
					elem.write(w)?;
				}
				Ok(())
			}
		}
	}
}
macro_rules! impl_readable_for_vec {
	($ty: ty $(, $name: ident)*) => {
		impl<$($name : Readable),*> Readable for Vec<$ty> {
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let len: CollectionLength = Readable::read(r)?;
				let mut ret = Vec::with_capacity(cmp::min(len.0 as usize, MAX_BUF_SIZE / core::mem::size_of::<$ty>()));
				for _ in 0..len.0 {
					if let Some(val) = MaybeReadable::read(r)? {
						ret.push(val);
					}
				}
				Ok(ret)
			}
		}
	}
}
macro_rules! impl_for_vec {
	($ty: ty $(, $name: ident)*) => {
		impl_writeable_for_vec!($ty $(, $name)*);
		impl_readable_for_vec!($ty $(, $name)*);
	}
}

// Alternatives to impl_writeable_for_vec/impl_readable_for_vec that add a length prefix to each
// element in the Vec. Intended to be used when elements have variable lengths.
macro_rules! impl_writeable_for_vec_with_element_length_prefix {
	($ty: ty $(, $name: ident)*) => {
		impl<$($name : Writeable),*> Writeable for Vec<$ty> {
			#[inline]
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				CollectionLength(self.len() as u64).write(w)?;
				for elem in self.iter() {
					CollectionLength(elem.serialized_length() as u64).write(w)?;
					elem.write(w)?;
				}
				Ok(())
			}
		}
	}
}
macro_rules! impl_readable_for_vec_with_element_length_prefix {
	($ty: ty $(, $name: ident)*) => {
		impl<$($name : Readable),*> Readable for Vec<$ty> {
			#[inline]
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let len: CollectionLength = Readable::read(r)?;
				let mut ret = Vec::with_capacity(cmp::min(len.0 as usize, MAX_BUF_SIZE / core::mem::size_of::<$ty>()));
				for _ in 0..len.0 {
					let elem_len: CollectionLength = Readable::read(r)?;
					let mut elem_reader = FixedLengthReader::new(r, elem_len.0);
					ret.push(LengthReadable::read_from_fixed_length_buffer(&mut elem_reader)?);
				}
				Ok(ret)
			}
		}
	}
}
macro_rules! impl_for_vec_with_element_length_prefix {
	($ty: ty $(, $name: ident)*) => {
		impl_writeable_for_vec_with_element_length_prefix!($ty $(, $name)*);
		impl_readable_for_vec_with_element_length_prefix!($ty $(, $name)*);
	}
}

impl Writeable for Vec<u8> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.len() as u64).write(w)?;
		w.write_all(&self)
	}
}

impl Readable for Vec<u8> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut len: CollectionLength = Readable::read(r)?;
		let mut ret = Vec::new();
		while len.0 > 0 {
			let readamt = cmp::min(len.0 as usize, MAX_BUF_SIZE);
			let readstart = ret.len();
			ret.resize(readstart + readamt, 0);
			r.read_exact(&mut ret[readstart..])?;
			len.0 -= readamt as u64;
		}
		Ok(ret)
	}
}

impl_for_vec!(ecdsa::Signature);
impl_for_vec!(crate::chain::channelmonitor::ChannelMonitorUpdate);
impl_for_vec!(crate::ln::channelmanager::MonitorUpdateCompletionAction);
impl_for_vec!(crate::ln::channelmanager::PaymentClaimDetails);
impl_for_vec!(crate::ln::msgs::SocketAddress);
impl_for_vec!((A, B), A, B);
impl_for_vec!(SerialId);
impl_for_vec!(NegotiatedTxInput);
impl_for_vec!(InteractiveTxOutput);
impl_writeable_for_vec!(&crate::routing::router::BlindedTail);
impl_readable_for_vec!(crate::routing::router::BlindedTail);
impl_for_vec!(crate::routing::router::TrampolineHop);
impl_for_vec_with_element_length_prefix!(crate::ln::msgs::UpdateAddHTLC);
impl_writeable_for_vec_with_element_length_prefix!(&crate::ln::msgs::UpdateAddHTLC);
impl_for_vec!(u32);

impl Writeable for Vec<Witness> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		(self.len() as u16).write(w)?;
		for witness in self {
			(witness.size() as u16).write(w)?;
			witness.write(w)?;
		}
		Ok(())
	}
}

impl Readable for Vec<Witness> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let num_witnesses = <u16 as Readable>::read(r)? as usize;
		let mut witnesses = Vec::with_capacity(num_witnesses);
		for _ in 0..num_witnesses {
			// Even though the length of each witness can be inferred in its consensus-encoded form,
			// the spec includes a length prefix so that implementations don't have to deserialize
			//  each initially. We do that here anyway as in general we'll need to be able to make
			// assertions on some properties of the witnesses when receiving a message providing a list
			// of witnesses. We'll just do a sanity check for the lengths and error if there is a mismatch.
			let witness_len = <u16 as Readable>::read(r)? as usize;
			let witness = <Witness as Readable>::read(r)?;
			if witness.size() != witness_len {
				return Err(DecodeError::BadLengthDescriptor);
			}
			witnesses.push(witness);
		}
		Ok(witnesses)
	}
}

impl Writeable for ScriptBuf {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		(self.len() as u16).write(w)?;
		w.write_all(self.as_bytes())
	}
}

impl Readable for ScriptBuf {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len = <u16 as Readable>::read(r)? as usize;
		let mut buf = vec![0; len];
		r.read_exact(&mut buf)?;
		Ok(ScriptBuf::from(buf))
	}
}

impl Writeable for PublicKey {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.serialize().write(w)
	}
	#[inline]
	fn serialized_length(&self) -> usize {
		PUBLIC_KEY_SIZE
	}
}

impl Readable for PublicKey {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; PUBLIC_KEY_SIZE] = Readable::read(r)?;
		match PublicKey::from_slice(&buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for SecretKey {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let mut ser = [0; SECRET_KEY_SIZE];
		ser.copy_from_slice(&self[..]);
		ser.write(w)
	}
	#[inline]
	fn serialized_length(&self) -> usize {
		SECRET_KEY_SIZE
	}
}

impl Readable for SecretKey {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; SECRET_KEY_SIZE] = Readable::read(r)?;
		match SecretKey::from_slice(&buf) {
			Ok(key) => Ok(key),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

#[cfg(taproot)]
impl Writeable for musig2::types::PublicNonce {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.serialize().write(w)
	}
}

#[cfg(taproot)]
impl Readable for musig2::types::PublicNonce {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; PUBLIC_KEY_SIZE * 2] = Readable::read(r)?;
		musig2::types::PublicNonce::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)
	}
}

#[cfg(taproot)]
impl Writeable for PartialSignatureWithNonce {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.serialize().write(w)?;
		self.1.write(w)
	}
}

#[cfg(taproot)]
impl Readable for PartialSignatureWithNonce {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let partial_signature_buf: [u8; SECRET_KEY_SIZE] = Readable::read(r)?;
		let partial_signature = musig2::types::PartialSignature::from_slice(&partial_signature_buf)
			.map_err(|_| DecodeError::InvalidValue)?;
		let public_nonce: musig2::types::PublicNonce = Readable::read(r)?;
		Ok(PartialSignatureWithNonce(partial_signature, public_nonce))
	}
}

impl Writeable for Hmac<Sha256> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for Hmac<Sha256> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(Hmac::<Sha256>::from_byte_array(buf))
	}
}

impl Writeable for Sha256dHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for Sha256dHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(Sha256dHash::from_slice(&buf[..]).unwrap())
	}
}

impl Writeable for ecdsa::Signature {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.serialize_compact().write(w)
	}
}

impl Readable for ecdsa::Signature {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; COMPACT_SIGNATURE_SIZE] = Readable::read(r)?;
		match ecdsa::Signature::from_compact(&buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for schnorr::Signature {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.as_ref().write(w)
	}
}

impl Readable for schnorr::Signature {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; SCHNORR_SIGNATURE_SIZE] = Readable::read(r)?;
		match schnorr::Signature::from_slice(&buf) {
			Ok(sig) => Ok(sig),
			Err(_) => return Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for PaymentPreimage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentPreimage {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentPreimage(buf))
	}
}

impl Writeable for PaymentHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentHash(buf))
	}
}

impl Writeable for PaymentSecret {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PaymentSecret {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(PaymentSecret(buf))
	}
}

impl<T: Writeable> Writeable for Box<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		T::write(&**self, w)
	}
}

impl<T: Readable> Readable for Box<T> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Box::new(Readable::read(r)?))
	}
}

impl<T: Writeable> Writeable for Option<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match *self {
			None => 0u8.write(w)?,
			Some(ref data) => {
				BigSize(data.serialized_length() as u64 + 1).write(w)?;
				data.write(w)?;
			},
		}
		Ok(())
	}
}

impl<T: LengthReadable> Readable for Option<T> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: BigSize = Readable::read(r)?;
		match len.0 {
			0 => Ok(None),
			len => {
				let mut reader = FixedLengthReader::new(r, len - 1);
				Ok(Some(LengthReadable::read_from_fixed_length_buffer(&mut reader)?))
			},
		}
	}
}

impl Writeable for AbsoluteLockTime {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.to_consensus_u32().write(w)
	}
}

impl Readable for AbsoluteLockTime {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let lock_time: u32 = Readable::read(r)?;
		Ok(AbsoluteLockTime::from_consensus(lock_time))
	}
}

impl Writeable for Amount {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.to_sat().write(w)
	}
}

impl Readable for Amount {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let amount: u64 = Readable::read(r)?;
		Ok(Amount::from_sat(amount))
	}
}

impl Writeable for Weight {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.to_wu().write(w)
	}
}

impl Readable for Weight {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let wu: u64 = Readable::read(r)?;
		Ok(Weight::from_wu(wu))
	}
}

impl Writeable for Txid {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for Txid {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(Txid::from_slice(&buf[..]).unwrap())
	}
}

impl Writeable for BlockHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self[..])
	}
}

impl Readable for BlockHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		use bitcoin::hashes::Hash;

		let buf: [u8; 32] = Readable::read(r)?;
		Ok(BlockHash::from_slice(&buf[..]).unwrap())
	}
}

impl Writeable for ChainHash {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(self.as_bytes())
	}
}

impl Readable for ChainHash {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(ChainHash::from(buf))
	}
}

impl Writeable for OutPoint {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.txid.write(w)?;
		self.vout.write(w)?;
		Ok(())
	}
}

impl Readable for OutPoint {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let txid = Readable::read(r)?;
		let vout = Readable::read(r)?;
		Ok(OutPoint { txid, vout })
	}
}

macro_rules! impl_consensus_ser {
	($bitcoin_type: ty) => {
		impl Writeable for $bitcoin_type {
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
				match self.consensus_encode(&mut WriterWriteAdaptor(writer)) {
					Ok(_) => Ok(()),
					Err(e) => Err(e),
				}
			}
		}

		impl Readable for $bitcoin_type {
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				let mut reader = BufReader::<_>::new(r);
				match consensus::encode::Decodable::consensus_decode(&mut reader) {
					Ok(t) => Ok(t),
					Err(consensus::encode::Error::Io(ref e))
						if e.kind() == io::ErrorKind::UnexpectedEof =>
					{
						Err(DecodeError::ShortRead)
					},
					Err(consensus::encode::Error::Io(e)) => Err(DecodeError::Io(e.kind().into())),
					Err(_) => Err(DecodeError::InvalidValue),
				}
			}
		}
	};
}
impl_consensus_ser!(Transaction);
impl_consensus_ser!(TxIn);
impl_consensus_ser!(TxOut);
impl_consensus_ser!(Witness);

impl<T: Readable> Readable for Mutex<T> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let t: T = Readable::read(r)?;
		Ok(Mutex::new(t))
	}
}
impl<T: Writeable> Writeable for Mutex<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.lock().unwrap().write(w)
	}
}

impl<T: Readable> Readable for RwLock<T> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let t: T = Readable::read(r)?;
		Ok(RwLock::new(t))
	}
}
impl<T: Writeable> Writeable for RwLock<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.read().unwrap().write(w)
	}
}

macro_rules! impl_tuple_ser {
	($($i: ident : $type: tt),*) => {
		impl<$($type),*> Readable for ($($type),*)
		where $(
			$type: Readable,
		)*
		{
			fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
				Ok(($(<$type as Readable>::read(r)?),*))
			}
		}

		impl<$($type),*> Writeable for ($($type),*)
		where $(
			$type: Writeable,
		)*
		{
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				let ($($i),*) = self;
				$($i.write(w)?;)*
				Ok(())
			}
		}
	}
}

impl_tuple_ser!(a: A, b: B);
impl_tuple_ser!(a: A, b: B, c: C);
impl_tuple_ser!(a: A, b: B, c: C, d: D);
impl_tuple_ser!(a: A, b: B, c: C, d: D, e: E);
impl_tuple_ser!(a: A, b: B, c: C, d: D, e: E, f: F);
impl_tuple_ser!(a: A, b: B, c: C, d: D, e: E, f: F, g: G);

impl Writeable for () {
	fn write<W: Writer>(&self, _: &mut W) -> Result<(), io::Error> {
		Ok(())
	}
}
impl Readable for () {
	fn read<R: Read>(_r: &mut R) -> Result<Self, DecodeError> {
		Ok(())
	}
}

impl Writeable for String {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.len() as u64).write(w)?;
		w.write_all(self.as_bytes())
	}
}
impl Readable for String {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let v: Vec<u8> = Readable::read(r)?;
		let ret = String::from_utf8(v).map_err(|_| DecodeError::InvalidValue)?;
		Ok(ret)
	}
}

/// Represents a hostname for serialization purposes.
/// Only the character set and length will be validated.
/// The character set consists of ASCII alphanumeric characters, hyphens, and periods.
/// Its length is guaranteed to be representable by a single byte.
/// This serialization is used by [`BOLT 7`] hostnames.
///
/// [`BOLT 7`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Hostname(String);
impl Hostname {
	/// Returns the length of the hostname.
	pub fn len(&self) -> u8 {
		(&self.0).len() as u8
	}

	/// Check if the chars in `s` are allowed to be included in a [`Hostname`].
	pub(crate) fn str_is_valid_hostname(s: &str) -> bool {
		s.len() <= 255
			&& s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
	}
}

impl core::fmt::Display for Hostname {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}", self.0)?;
		Ok(())
	}
}
impl Deref for Hostname {
	type Target = String;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}
impl From<Hostname> for String {
	fn from(hostname: Hostname) -> Self {
		hostname.0
	}
}
impl TryFrom<Vec<u8>> for Hostname {
	type Error = ();

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		if let Ok(s) = String::from_utf8(bytes) {
			Hostname::try_from(s)
		} else {
			Err(())
		}
	}
}
impl TryFrom<String> for Hostname {
	type Error = ();

	fn try_from(s: String) -> Result<Self, Self::Error> {
		if Hostname::str_is_valid_hostname(&s) {
			Ok(Hostname(s))
		} else {
			Err(())
		}
	}
}
impl Writeable for Hostname {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.len().write(w)?;
		w.write_all(self.as_bytes())
	}
}
impl Readable for Hostname {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Hostname, DecodeError> {
		let len: u8 = Readable::read(r)?;
		let mut vec = Vec::with_capacity(len.into());
		vec.resize(len.into(), 0);
		r.read_exact(&mut vec)?;
		Hostname::try_from(vec).map_err(|_| DecodeError::InvalidValue)
	}
}

impl TryInto<Name> for Hostname {
	type Error = ();
	fn try_into(self) -> Result<Name, ()> {
		Name::try_from(self.0)
	}
}

/// This is not exported to bindings users as `Duration`s are simply mapped as ints.
impl Writeable for Duration {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.as_secs().write(w)?;
		self.subsec_nanos().write(w)
	}
}
/// This is not exported to bindings users as `Duration`s are simply mapped as ints.
impl Readable for Duration {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let secs = Readable::read(r)?;
		let nanos = Readable::read(r)?;
		Ok(Duration::new(secs, nanos))
	}
}

/// A wrapper for a `Transaction` which can only be constructed with [`TransactionU16LenLimited::new`]
/// if the `Transaction`'s consensus-serialized length is <= u16::MAX.
///
/// Use [`TransactionU16LenLimited::into_transaction`] to convert into the contained `Transaction`.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct TransactionU16LenLimited(Transaction);

impl TransactionU16LenLimited {
	/// Constructs a new `TransactionU16LenLimited` from a `Transaction` only if it's consensus-
	/// serialized length is <= u16::MAX.
	pub fn new(transaction: Transaction) -> Result<Self, ()> {
		if transaction.serialized_length() > (u16::MAX as usize) {
			Err(())
		} else {
			Ok(Self(transaction))
		}
	}

	/// Consumes this `TransactionU16LenLimited` and returns its contained `Transaction`.
	pub fn into_transaction(self) -> Transaction {
		self.0
	}

	/// Returns a reference to the contained `Transaction`
	pub fn as_transaction(&self) -> &Transaction {
		&self.0
	}
}

impl Writeable for Option<TransactionU16LenLimited> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Some(tx) => {
				(tx.0.serialized_length() as u16).write(w)?;
				tx.0.write(w)
			},
			None => 0u16.write(w),
		}
	}
}

impl Readable for Option<TransactionU16LenLimited> {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len = <u16 as Readable>::read(r)?;
		if len == 0 {
			return Ok(None);
		}
		let mut tx_reader = FixedLengthReader::new(r, len as u64);
		let tx: Transaction = Readable::read(&mut tx_reader)?;
		if tx_reader.bytes_remain() {
			Err(DecodeError::BadLengthDescriptor)
		} else {
			Ok(Some(TransactionU16LenLimited(tx)))
		}
	}
}

impl Writeable for ClaimId {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.0.write(writer)
	}
}

impl Readable for ClaimId {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(Readable::read(reader)?))
	}
}

#[cfg(test)]
mod tests {
	use crate::prelude::*;
	use crate::util::ser::{Hostname, Readable, Writeable};
	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::ecdsa;

	#[test]
	fn hostname_conversion() {
		assert_eq!(Hostname::try_from(String::from("a-test.com")).unwrap().as_str(), "a-test.com");

		assert!(Hostname::try_from(String::from("\"")).is_err());
		assert!(Hostname::try_from(String::from("$")).is_err());
		assert!(Hostname::try_from(String::from("⚡")).is_err());
		let mut large_vec = Vec::with_capacity(256);
		large_vec.resize(256, b'A');
		assert!(Hostname::try_from(String::from_utf8(large_vec).unwrap()).is_err());
	}

	#[test]
	fn hostname_serialization() {
		let hostname = Hostname::try_from(String::from("test")).unwrap();
		let mut buf: Vec<u8> = Vec::new();
		hostname.write(&mut buf).unwrap();
		assert_eq!(Hostname::read(&mut buf.as_slice()).unwrap().as_str(), "test");
	}

	#[test]
	/// Taproot will likely fill legacy signature fields with all 0s.
	/// This test ensures that doing so won't break serialization.
	fn null_signature_codec() {
		let buffer = vec![0u8; 64];
		let mut cursor = crate::io::Cursor::new(buffer.clone());
		let signature = ecdsa::Signature::read(&mut cursor).unwrap();
		let serialization = signature.serialize_compact();
		assert_eq!(buffer, serialization.to_vec())
	}

	#[test]
	fn bigsize_encoding_decoding() {
		let values = [0, 252, 253, 65535, 65536, 4294967295, 4294967296, 18446744073709551615];
		let bytes = [
			"00",
			"fc",
			"fd00fd",
			"fdffff",
			"fe00010000",
			"feffffffff",
			"ff0000000100000000",
			"ffffffffffffffffff",
		];
		for i in 0..=7 {
			let mut stream = crate::io::Cursor::new(<Vec<u8>>::from_hex(bytes[i]).unwrap());
			assert_eq!(super::BigSize::read(&mut stream).unwrap().0, values[i]);
			let mut stream = super::VecWriter(Vec::new());
			super::BigSize(values[i]).write(&mut stream).unwrap();
			assert_eq!(stream.0, <Vec<u8>>::from_hex(bytes[i]).unwrap());
		}
		let err_bytes = [
			"fd00fc",
			"fe0000ffff",
			"ff00000000ffffffff",
			"fd00",
			"feffff",
			"ffffffffff",
			"fd",
			"fe",
			"ff",
			"",
		];
		for i in 0..=9 {
			let mut stream = crate::io::Cursor::new(<Vec<u8>>::from_hex(err_bytes[i]).unwrap());
			if i < 3 {
				assert_eq!(
					super::BigSize::read(&mut stream).err(),
					Some(crate::ln::msgs::DecodeError::InvalidValue)
				);
			} else {
				assert_eq!(
					super::BigSize::read(&mut stream).err(),
					Some(crate::ln::msgs::DecodeError::ShortRead)
				);
			}
		}
	}
}
