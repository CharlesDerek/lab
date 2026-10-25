//! A small bounded tree for EvtRenderEventXml. This accepts predefined XML
//! escapes and character references, but never DTDs or custom entities.
use super::{EVENT_NAMESPACE, MAX_XML_BYTES};
use quick_xml::{events::Event, Reader};
use std::collections::BTreeMap;

const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 512;
const MAX_TEXT: usize = 4096;

pub(super) struct Node {
    pub name: String,
    namespace: String,
    pub attributes: BTreeMap<String, String>,
    text: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn require(&self, name: &str) -> Result<(), String> {
        if self.name != name
            || self.namespace != EVENT_NAMESPACE
            || !self.text.chars().all(char::is_whitespace)
        {
            return Err("Invalid Windows XML element or namespace".into());
        }
        Ok(())
    }

    pub fn require_empty(&self, name: &str) -> Result<(), String> {
        if self.leaf(name)?.is_empty() {
            Ok(())
        } else {
            Err("Unexpected Windows XML field content".into())
        }
    }

    pub fn leaf(&self, name: &str) -> Result<&str, String> {
        if self.name != name || self.namespace != EVENT_NAMESPACE || !self.children.is_empty() {
            return Err("Invalid Windows XML leaf or namespace".into());
        }
        Ok(&self.text)
    }

    pub fn attribute(&self, name: &str) -> Result<&str, String> {
        self.attributes
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| "Missing Windows XML attribute".into())
    }

    pub fn one(&self, name: &str) -> Result<&Self, String> {
        let mut matching = self.children.iter().filter(|child| child.name == name);
        let found = matching.next().ok_or("Missing Windows XML field")?;
        if matching.next().is_some() {
            return Err("Duplicate Windows XML field".into());
        }
        Ok(found)
    }
}

fn valid_character(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r') || (!ch.is_control() && ch != '\u{fffe}' && ch != '\u{ffff}')
}

fn name(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty()
        || bytes.len() > 128
        || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_:-.".contains(b))
    {
        return Err("Invalid Windows XML name".into());
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| "Invalid Windows XML name".into())
}

fn append(stack: &mut [Node], value: &str) -> Result<(), String> {
    if !value.chars().all(valid_character) {
        return Err("Invalid Windows XML character".into());
    }
    if let Some(node) = stack.last_mut() {
        if node.text.len().saturating_add(value.len()) > MAX_TEXT {
            return Err("Windows XML text exceeds limit".into());
        }
        node.text.push_str(value);
    } else if !value
        .chars()
        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
    {
        return Err("Unexpected text outside Windows XML event".into());
    }
    Ok(())
}

pub(super) fn parse(input: &str) -> Result<Node, String> {
    if input.is_empty() || input.len() > MAX_XML_BYTES || !input.chars().all(valid_character) {
        return Err("Invalid Windows XML size or characters".into());
    }
    let mut reader = Reader::from_str(input);
    reader.config_mut().check_end_names = true;
    reader.config_mut().check_comments = true;
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut nodes = 0;
    let mut declaration = false;
    loop {
        match reader.read_event().map_err(|_| "Malformed Windows XML")? {
            Event::Start(start) => {
                nodes += 1;
                if nodes > MAX_NODES
                    || stack.len() >= MAX_DEPTH
                    || (stack.is_empty() && root.is_some())
                {
                    return Err("Windows XML structure exceeds limits".into());
                }
                let mut attributes = BTreeMap::new();
                for attribute in start.attributes() {
                    let attribute = attribute.map_err(|_| "Malformed Windows XML attribute")?;
                    let key = name(attribute.key.as_ref())?;
                    let value = attribute
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(|_| "Invalid Windows XML attribute value")?
                        .into_owned();
                    if value.len() > MAX_TEXT
                        || !value.chars().all(valid_character)
                        || attributes.insert(key, value).is_some()
                        || attributes.len() > 16
                    {
                        return Err("Invalid or oversized Windows XML attributes".into());
                    }
                }
                let namespace = attributes.get("xmlns").cloned().unwrap_or_else(|| {
                    stack
                        .last()
                        .map(|n| n.namespace.clone())
                        .unwrap_or_default()
                });
                stack.push(Node {
                    name: name(start.name().as_ref())?,
                    namespace,
                    attributes,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Event::End(_) => {
                let node = stack.pop().ok_or("Unbalanced Windows XML")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return Err("Multiple Windows XML roots".into());
                }
            }
            Event::Text(text) => append(
                &mut stack,
                &text.xml_content().map_err(|_| "Invalid Windows XML text")?,
            )?,
            Event::CData(text) => {
                if stack.is_empty() {
                    return Err("Unexpected Windows XML CDATA".into());
                }
                append(
                    &mut stack,
                    &text
                        .xml_content()
                        .map_err(|_| "Invalid Windows XML CDATA")?,
                )?;
            }
            Event::GeneralRef(reference) => {
                if stack.is_empty() {
                    return Err("Unexpected Windows XML reference".into());
                }
                let resolved = reference
                    .resolve_char_ref()
                    .map_err(|_| "Invalid XML character reference")?;
                let ch = match resolved {
                    Some(ch) => ch,
                    None => match reference.as_ref() {
                        b"amp" => '&',
                        b"lt" => '<',
                        b"gt" => '>',
                        b"apos" => '\'',
                        b"quot" => '"',
                        _ => return Err("Custom XML entities are forbidden".into()),
                    },
                };
                append(&mut stack, ch.encode_utf8(&mut [0; 4]))?;
            }
            Event::Decl(value) => {
                if declaration
                    || nodes != 0
                    || root.is_some()
                    || value.version().ok().as_deref() != Some(b"1.0")
                    || value
                        .encoding()
                        .is_some_and(|v| v.map_or(true, |v| !v.eq_ignore_ascii_case(b"utf-8")))
                {
                    return Err("Unsupported Windows XML declaration".into());
                }
                declaration = true;
            }
            Event::Comment(_) => {}
            Event::Eof => break,
            Event::DocType(_) | Event::PI(_) | Event::Empty(_) => {
                return Err("Unsupported Windows XML construct".into());
            }
        }
    }
    if !stack.is_empty() {
        return Err("Unclosed Windows XML elements".into());
    }
    root.ok_or_else(|| "Missing Windows XML event".into())
}
