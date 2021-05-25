use log::{trace, debug};

use std::path::Path;
use goblin::Object;
use std::fs;

pub fn find_addr_by_sym(bin: &str, sym_name: &str) -> Result<u64, goblin::error::Error> {
    let path = Path::new(bin);
    let buffer = fs::read(path)?;

    if let Object::Elf(elf) = Object::parse(&buffer)? {
        for sym in elf.dynsyms.iter() {
            if let Some(opt_name) = elf.dynstrtab.get(sym.st_name) {
                let name = opt_name?;
                trace!("sym {}", name);
                if sym_name == name {
                    debug!("found symbol {} in bin {} at {:#x}", name, bin, sym.st_value);
                    return Ok(sym.st_value);
                }
            }
        }
    } else {
        return Err(goblin::error::Error::Malformed(
            "Binary is not an elf".to_string(),
        ));
    }

    return Err(goblin::error::Error::Malformed(
        "Coud not find symbol".to_string(),
    ));
}
