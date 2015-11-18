//! ## tl;dr
//!
//! cookie-rs percent-decodes a cookie's key and value,
//! it later only re-encodes the value.
//! No such encoding/decoding is defined for cookies.
//! Applications relying on the parser might break,
//! e.g. Servo doesn't use cookie-rs' formatting
//! and might send cookies with invalid characters back.
//!
//! ---
//!
//! # A bug
//!
//! It turns out cookie-rs handles Cookies in a rather unexpected way,
//! which in turn breaks other systems, such as Servo, that rely on cookie-rs
//! to do the parsing only, but no encoding/decoding of a cookie's contents.
//!
//! # Cookie Theory
//!
//! The latest "definitive specification for cookies as used
//! in the real world was published" (according to Wikipedia)
//! is [RFC6265](https://tools.ietf.org/html/rfc6265),
//! "HTTP State Management Mechanism".
//!
//! A cookie as sent in an HTTP header is defined by
//!
//! ```text
//! cookie-pair       = cookie-name "=" cookie-value
//! cookie-name       = token
//! cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE  )
//! ```
//!
//! `token` is defined in another RFC as
//!
//! ```text
//! token          = 1*<any CHAR except CTLs or separators>
//! ```
//!
//! with `CHAR` being every US-ASCII character and CTL being control characters
//! (including carriage return `\r` and linefeed `\n`)
//!
//! A cookie-octet is represented as:
//!
//! ```text
//! cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//! ```
//!
//! That is:
//! US-ASCII characters excluding control characters, whitespace, comma,
//! semicolon and backslash.
//! That leaves a whole lot of characters to be used,
//! especially the percent sign `%` (aka `%x25`).
//!
//! The same `cookie-pair` description is used
//! for the header sent back to a server.
//!
//! The RFC also contains a description on how to properly parse HTTP headers
//! to extract a cookie's key-value pair.
//! It relaxes a bit from the above format,
//! so even servers not conforming to it will still be usable.
//!
//! At no point does the RFC talk about any encoding or interpretation
//! of the values.
//!
//! It has this hint though:
//!
//! > NOTE: Despite its name, the cookie-string is actually a sequence of
//! > octets, not a sequence of characters.
//! > To convert the cookie-string
//! > (or components thereof) into a sequence of characters (e.g., for
//! > presentation to the user), the user agent might wish to try using the
//! > UTF-8 character encoding
//!
//! Note: any such decoding should be for presentation to the user.
//! The string has to be used unmodified when used in a HTTP header.
//!
//! # Cookie-rs
//!
//! [Cookie-rs](https://github.com/alexcrichton/cookie-rs) is a library for
//! HTTP cookie parsing and cookie jar management for rust.
//!
//! It's also used by [Hyper](https://github.com/hyperium/hyper),
//! which in turn is used in [Servo](https://github.com/servo/servo).
//!
//! Usage is easy:
//!
//!
//! ```rust
//! let cookie_str = "key=value";
//! let cookie = Cookie::parse(cookie_str).unwrap();
//! ```
//!
//! This gives you a cookie object with access to all relevant fields,
//! especially the key and value.
//!
//! But hidden in the code and no where documented,
//! it percent-decodes everything.
//!
//! ```rust
//! let cookie_str = "key=value%23foobar";
//! let cookie = Cookie::parse(cookie_str).unwrap();
//! assert_eq!("value#foobar", cookie.value); // Unexpected.
//! ```
//!
//! It does so for the key as well.
//! This will also re-encode the value using percent-encoding.
//!
//! It also comes with a handy method to format a cookie again:
//!
//! ```rust
//! let cookie = Cookie::new("key".into(), "value#foobar".into());
//! assert_eq!("key=value%23foobar", format!("{}", cookie));
//! ```
//!
//! Though it does not do this percent-reencoding for the value.
//!
//! ```rust
//! let cookie = Cookie::new("key#foobar".into(), "value".into());
//! assert_eq!("key#foobar=value", format!("{}", cookie));
//! ```
//!
//! The decoding was introduced a long time ago in
//! [724003de](https://github.com/alexcrichton/cookie-rs/commit/724003decad72cdbe3f998b0b8d181682e9582c5).
//!
//! # Servo
//!
//! Servo relies on Hyper and cookie-rs to do the right thing
//! with HTTP requests and parsing of the data.
//!
//! Because it's a browser it also stores the cookies and sends them back
//! to the server as necessary.
//!
//! It also [properly follows the exact steps](https://github.com/servo/servo/blob/2be0cb7827c6553b7dfa4d641bf3a1c72372ad3b/components/net/cookie_storage.rs#L87-L117)
//! to generate the cookie header as written in the RFC.
//! And in the end it just concatenates the key and value.
//!
//! ```rust
//! (match acc.len() {
//!     0 => acc,
//!     _ => acc + ";"
//! }) + &c.cookie.name + "=" + &c.cookie.value
//! ```
//!
//! `c.cookie` is already a `Cookie` object, as parsed by `cookie-rs`.
//! This means all the above mentioned percent-decoding was already applied.
//! But because it direclty uses the strings in the object,
//! no re-encoding is applied anymore.
//!
//! Now consider a server sending a string containing percent symbols (`%`),
//! maybe even something that actually looks like a
//! properly percent-encoded value (`%0A = \n`).
//! Interpretation of this string is totally up to the server.
//! It expects to get the exact same string back from the client.
//!
//! Instead it gets a percent-decoded, but not re-encoded value back.
//!
//! Therefore Servo will fail to adhere to the RFC and breaks application
//! expecting their cookies back.
//!
//! The following cookies cause problems when Servo receives them
//! and later sends them back.
//!
//! ```
//! Cookie::parse("key=value%eefoobar") // After percent-decoding it's not valid UTF-8
//!                                     // and therefore not a valid String
//!                                     // Servo will just not save it.
//!                                     // → Cookie lost.
//!
//! Cookie::parse("key=value%0Afoobar") // After percent-decoding it contains
//!                                     // a newline.
//!                                     // Servo will insert it as is,
//!                                     // breaking the whole `Cookie` header
//!                                     // → Cookie is invalid on server-side
//! ```
//!
//! # Solutions
//!
//! The best thing would be to separate the different steps in cookie-rs.
//! Provide one layer for parsing only, solely dealing with byte arrays.
//! This layer would be used by Servo and would just work.
//!
//! Another layer on top could help with an actual decoding
//! or turning cookies into strings.
//! But at this point it's up to the application to decide.
//!
//! Of course the above would be a breaking change of cookie-rs
//! (even though this behaviour is not documented at all).
//! Right now there are only 6 reverse-dependencies on crates.io plus Servo.
//! I didn't check usage in any of them to see if above solution would break
//! more stuff.
//!
//! To keep cookie-rs as is (but maybe atleast document its behavior),
//! a new low-level library could be used
//! (which in turn makes cookie-rs just a user of this library).
//! No one depending on cookie-rs directly would be affected,
//! but Servo could be fixed.
//!
//! Note: Even re-encoding the cookie when inserted as a header by Servo
//! would not help, because of cookies not decoding to proper UTF-8.
extern crate cookie;

use cookie::Cookie;

/// It can parse cookies easily
#[cfg_attr(test, test)]
pub fn _01_simple() {
    let cookie_str = "key=value";

    let cookie = Cookie::parse(cookie_str).unwrap();

    assert_eq!("key", cookie.name);
    assert_eq!("value", cookie.value);
}

/// But it decodes the value
#[cfg_attr(test, test)]
pub fn _02_value_percent() {
    let cookie_str = "key=value%2Ffoobar";

    let cookie = Cookie::parse(cookie_str).unwrap();

    assert_eq!("key", cookie.name);
    assert_eq!("value%2Ffoobar", cookie.value);
}

/// And it fails if the value doesn't hold a valid percent-encoded string
#[cfg_attr(test, test)]
pub fn _03_value_single_percent() {
    let cookie_str = "key=value%foobar";

    let cookie = Cookie::parse(cookie_str).unwrap();

    assert_eq!("key", cookie.name);
    assert_eq!("value%2Ffoobar", cookie.value);
}

/// The same is true for the key: it's decoded.
#[cfg_attr(test, test)]
pub fn _04_key_percent() {
    let cookie_str = "key%2Ffoobar=value";

    let cookie = Cookie::parse(cookie_str).unwrap();

    assert_eq!("key%2Ffoobar", cookie.name);
    assert_eq!("value", cookie.value);
}

/// cookie-rs comes with a handy method to display a cookie.
/// It does so by formatting as you expect.
/// (It even includes the additional data used in a `Set-Cookie` header)
#[cfg_attr(test, test)]
pub fn _05_format() {
    let cookie = Cookie::new("key".into(), "value".into());
    assert_eq!("key=value", format!("{}", cookie));
}

/// If it gets a percent-encoded string like `value%2Ffoobar`,
/// everything is fine, because none of the characters gets
/// percent-encoded again.
#[cfg_attr(test, test)]
pub fn _06_format_perc() {
    let cookie = Cookie::new("key".into(), "value%2Ffoobar".into());
    assert_eq!("key=value%2Ffoobar", format!("{}", cookie));
}

/// But if it has a value like `value#foobar`,
/// the `#` gets encoded.
#[cfg_attr(test, test)]
pub fn _07_format_hash() {
    let cookie = Cookie::new("key".into(), "value#foobar".into());
    assert_eq!("key=value#foobar", format!("{}", cookie));
}

/// Funnily enough: percent-encoding on display is only applied to the value,
/// the key is passed through unmodified.
#[cfg_attr(test, test)]
pub fn _08_format_hash_key() {
    let cookie = Cookie::new("key#foobar".into(), "value".into());
    assert_eq!("key#foobar=value", format!("{}", cookie));
}

/// Because it expects to get a proper string,
/// it fails to build up a cookie
#[cfg_attr(test, test)]
pub fn _09_invalid_utf8() {
    let cookie_str = "ke%y=a%eeb";
    let cookie = Cookie::parse(cookie_str).unwrap();

    assert_eq!("a%eeb", cookie.value);
}

/// And now it also inserts a newline
#[cfg_attr(test, test)]
pub fn _10_newline() {
    let cookie_str = "ke%y=a%0Ab";
    let cookie = Cookie::parse(cookie_str).unwrap();

    assert_eq!("a%0Ab", cookie.value);
}
