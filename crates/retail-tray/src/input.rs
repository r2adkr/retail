pub struct TextInput {
    pub value: String,
    pub placeholder: &'static str,
    /// Shown as bullets (auth keys)
    pub secret: bool,
    /// Byte offset of the caret, always on a char boundary
    caret: usize,
    /// Set by Ctrl/Cmd+A so the next edit replaces everything
    all_selected: bool,
}

impl TextInput {
    pub fn new(placeholder: &'static str, secret: bool) -> Self {
        TextInput { value: String::new(), placeholder, secret, caret: 0, all_selected: false }
    }

    pub fn set(&mut self, value: &str) {
        self.value = value.to_string();
        self.caret = self.value.len();
        self.all_selected = false;
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    pub fn trimmed(&self) -> &str {
        self.value.trim()
    }

    fn take_selection(&mut self) -> bool {
        if std::mem::take(&mut self.all_selected) {
            self.value.clear();
            self.caret = 0;
            true
        } else {
            false
        }
    }

    /// Drops control characters, including newlines
    pub fn insert(&mut self, text: &str) {
        let clean: String = text.chars().filter(|c| !c.is_control()).collect();
        if clean.is_empty() {
            return;
        }
        self.take_selection();
        self.value.insert_str(self.caret, &clean);
        self.caret += clean.len();
    }

    pub fn backspace(&mut self) {
        if self.take_selection() {
            return;
        }
        if let Some(c) = self.value[..self.caret].chars().next_back() {
            self.caret -= c.len_utf8();
            self.value.remove(self.caret);
        }
    }

    pub fn delete(&mut self) {
        if self.take_selection() {
            return;
        }
        if self.caret < self.value.len() {
            self.value.remove(self.caret);
        }
    }

    pub fn left(&mut self) {
        self.all_selected = false;
        if let Some(c) = self.value[..self.caret].chars().next_back() {
            self.caret -= c.len_utf8();
        }
    }

    pub fn right(&mut self) {
        self.all_selected = false;
        if let Some(c) = self.value[self.caret..].chars().next() {
            self.caret += c.len_utf8();
        }
    }

    pub fn home(&mut self) {
        self.all_selected = false;
        self.caret = 0;
    }

    pub fn end(&mut self) {
        self.all_selected = false;
        self.caret = self.value.len();
    }

    pub fn select_all(&mut self) {
        self.all_selected = !self.value.is_empty();
        self.caret = self.value.len();
    }

    pub fn is_all_selected(&self) -> bool {
        self.all_selected
    }

    /// The text as drawn, and the caret position within it (in chars)
    pub fn display(&self) -> (String, usize) {
        let caret_chars = self.value[..self.caret].chars().count();
        if self.secret {
            ("•".repeat(self.value.chars().count()), caret_chars)
        } else {
            (self.value.clone(), caret_chars)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing() {
        let mut t = TextInput::new("", false);
        t.insert("vpn.examle.com");
        for _ in 0..6 {
            t.left();
        }
        t.insert("p");
        assert_eq!(t.value, "vpn.example.com");
        t.home();
        t.insert("https://");
        assert_eq!(t.value, "https://vpn.example.com");
        t.end();
        t.backspace();
        t.delete(); // at end: no-op
        assert_eq!(t.value, "https://vpn.example.co");
        t.select_all();
        t.insert("x");
        assert_eq!(t.value, "x");
        t.select_all();
        t.backspace();
        assert_eq!(t.value, "");
    }

    #[test]
    fn multibyte_and_control_chars() {
        let mut t = TextInput::new("", true);
        t.insert("가나\n다\t");
        assert_eq!(t.value, "가나다");
        t.left();
        t.backspace();
        assert_eq!(t.value, "가다");
        assert_eq!(t.display(), ("••".to_string(), 1));
    }
}
