use libc::{c_char, c_void};
use std::mem;
use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


// TRAITS

/// Trait for different contexts
pub trait Context {
    fn get_handle(&self) -> *mut c_void;
    fn get_output_length(&self, input_len: usize) -> Result<usize>
    {
        context_get_output_length(self, input_len)
    }
}

/// Implementation of set padding
pub trait ContextWithPadding: Context {
    /// Sets the padding property.
    fn set_property_padding(&self, padding: &Padding) -> Result<()>
    {
        let value = conv::padding_rs_to_c(padding);
        context_set_property_single(self, types::Property::Padding, value)
    }
}

/// Implementation of rc2 property
pub trait ContextWithRc2Supported: Context {
    /// Sets the RC2 effective key bits property.
    fn set_property_rc2_effective_key_bits(&self, rc2_eff_key_bits: usize) -> Result<()>
    {
        context_set_property_single(self, types::Property::Rc2EffectiveKeyBits, rc2_eff_key_bits)
    }
}

/// Implementation of GCM/CCM set/get properties for encrypt/seal
pub trait ContextWithXcmEncryptProperties: Context {
    /// Sets the GCM AAD property.
    fn set_property_gcm_aad(&self, gcm_aad: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::GcmAad, gcm_aad)
    }
    /// Sets the GCM tag length property.
    fn set_property_gcm_tag_len(&self, gcm_tag_len: usize) -> Result<()>
    {
        context_set_property_single(self, types::Property::GcmTagLen, gcm_tag_len)
    }
    /// Sets the CCM AAD property.
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], input_len: usize) -> Result<()>;
    // {
    //     OPERATION_set_input_length(self, input_len)?;
    //     crypto::context_set_property_multiple(ctx, types::Property::CcmAad, ccm_aad)
    // }
    /// Sets the CCM tag length property.
    fn set_property_ccm_tag_len(&self, ccm_tag_len: usize) -> Result<()>
    {
        context_set_property_single(self, types::Property::CcmTagLen, ccm_tag_len)
    }
    /// Returns the GCM tag property.
    fn get_property_gcm_tag(&self) -> Result<Vec<u8>>
    {
        context_get_property_multiple(self, types::Property::GcmTag)
    }
    /// Returns the CCM tag property.
    fn get_property_ccm_tag(&self) -> Result<Vec<u8>>
    {
        context_get_property_multiple(self, types::Property::CcmTag)
    }
}

/// Implementation of all GCM/CCM properties for decrypt/open
pub trait ContextWithXcmDecryptProperties: Context {
    /// Sets the GCM AAD property.
    fn set_property_gcm_aad(&self, gcm_aad: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::GcmAad, gcm_aad)
    }
    /// Sets the GCM tag property.
    fn set_property_gcm_tag(&self, gcm_tag: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::GcmTag, gcm_tag)
    }
    /// Sets the CCM AAD property.
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], input_len: usize) -> Result<()>;
    // {
    //     OPERATION_set_input_length(self, input_len)?;
    //     crypto::context_set_property_multiple(ctx, types::Property::CcmAad, ccm_aad)
    // }
    /// Sets the CCM tag property.
    fn set_property_ccm_tag(&self, ccm_tag: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::CcmTag, ccm_tag)
    }
}


/// Initializes the library. Must be called before any other crypto
/// function. Should be called once in each thread that uses yaca.
pub fn initialize() -> Result<()>
{
    let r = unsafe {
        lib::yaca_initialize()
    };
    conv::res_c_to_rs(r)
}

/// Cleans up the library.
/// Must be called before exiting the thread that called yaca_initialize().
pub fn cleanup()
{
    unsafe {
        lib::yaca_cleanup()
    }
}

/// Safely compares first length bytes of two buffers.
pub fn memcmp(first: &[u8], second: &[u8], length: usize) -> Result<bool>
{
    let min = std::cmp::min(first.len(), second.len());
    assert!(length <= min);
    let first = first.as_ptr() as *const c_void;
    let second = second.as_ptr() as *const c_void;
    let r = unsafe {
        lib::yaca_memcmp(first, second, length)
    };
    conv::res_c_to_rs_bool(r)
}

/// Generates random data.
pub fn random_bytes(length: usize) -> Result<Vec<u8>>
{
    let mut v: Vec<u8> = Vec::with_capacity(length);
    let data = v.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_randomize_bytes(data, length)
    };
    conv::res_c_to_rs(r)?;
    unsafe {
        v.set_len(length);
    };
    Ok(v)
}

fn context_set_property_single<T, U>(ctx: &T, prop: types::Property,
                                     value: U) -> Result<()>
    where T: Context + ?Sized,
{
    let ctx = ctx.get_handle();
    let property = conv::property_rs_to_c(&prop);
    let value: *const U = &value;
    let value = value as *const c_void;
    let value_len = mem::size_of::<U>();
    let r = unsafe {
        lib::yaca_context_set_property(ctx, property, value, value_len)
    };
    conv::res_c_to_rs(r)
}

// Used by set_property_ccm_aad implementators
pub(crate) fn context_set_property_multiple<T, U>(ctx: &T, prop: types::Property,
                                           value: &[U]) -> Result<()>
    where T: Context + ?Sized,
{
    let ctx = ctx.get_handle();
    let property = conv::property_rs_to_c(&prop);
    let value_len = value.len() * mem::size_of::<U>();
    let value = value.as_ptr() as *const c_void;
    let r = unsafe {
        lib::yaca_context_set_property(ctx, property, value, value_len)
    };
    conv::res_c_to_rs(r)
}

fn context_get_property_multiple<T, U>(ctx: &T, prop: types::Property) -> Result<Vec<U>>
    where T: Context + ?Sized,
          U: Clone,
{
    let ctx = ctx.get_handle();
    let property = conv::property_rs_to_c(&prop);
    let mut value = ptr::null();
    let mut value_len = 0;
    let r = unsafe {
        lib::yaca_context_get_property(ctx, property, &mut value, &mut value_len)
    };
    conv::res_c_to_rs(r)?;
    let value_len = value_len / mem::size_of::<U>();
    let v = common::vector_from_raw(value_len, value);
    Ok(v)
}

fn context_get_output_length<T>(ctx: &T, input_len: usize) -> Result<usize>
    where T: Context + ?Sized,
{
    let mut output_len = 0;
    let ctx = ctx.get_handle();
    let r = unsafe {
        lib::yaca_context_get_output_length(ctx, input_len, &mut output_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(output_len)
}
