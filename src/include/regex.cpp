  // XSS Patterns
  static const regex script_tag_pattern("<\\s*script[^>]*>|<\\s*/\\s*script\\s*>", regex::icase);
  static const regex encoded_script_pattern("%(3c|3C)\\s*script", regex::icase);
  static const regex split_script_pattern("<\\s*\\w+\\s+<\\s*script|<\\s*/\\s*\\w+\\s+<\\s*script|<\\s*\\w+\\s+</\\s*script", regex::icase);
  static const regex expression_pattern("x?\\s*expression\\s*\\(|/\\s*x\\s*pression\\s*\\(", regex::icase);
  static const regex style_xss_pattern("style\\s*=.*(font-family|expression)[^;]*['\"(]", regex::icase);
  static const regex java_protocol_pattern("href\\s*=\\s*[\"']?\\s*java\\s*[:&]", regex::icase);
  static const regex encoded_event_pattern("%(6f|6F)(6e|6E)(l|4c)(o|4F)(a|41)(d|44)(%3d|=)", regex::icase);
  static const regex imap4_xss_pattern("x-imap4-modified-utf7.*(script|alert|java)", regex::icase);
  static const regex js_obfuscation_pattern("alert\\s*;\\s*pg\\s*\\(", regex::icase);
  static const regex event_handler_pattern("\\bon(load|error|click|mouseover|mouseout|focus|blur|submit|change|input|keydown|keyup|keypress|dblclick|drag|drop|scroll|touchstart|touchend|animationstart|transitionend)\\s*=", regex::icase);
  static const regex js_uri_pattern("(javascript|vbscript|data)\\s*:", regex::icase);
  static const regex html_tag_pattern("<\\s*(img|iframe|svg|object|embed|video|audio|body|input|marquee|isindex|form|button|select|textarea|table|div|span|a|font|center|applet|frameset|frame|layer|style|base|link|meta)", regex::icase);
  static const regex dangerous_func_pattern("\\b(alert|prompt|confirm|eval|setTimeout|setInterval|Function|document\\.write|innerHTML|outerHTML|execScript)\\s*\\(", regex::icase);
  static const regex encoding_pattern("String\\.fromCharCode|\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}|&#[0-9]+;|&#x[0-9a-fA-F]+;", regex::icase);
  static const regex css_injection_pattern("expression\\s*\\(|url\\s*\\(\\s*javascript:|behavior\\s*:|moz-binding\\s*:", regex::icase);
  static const regex dom_manipulation_pattern("\\b(document\\.cookie|document\\.domain|window\\.location|document\\.location|window\\.name)\\b", regex::icase);

  // SQL
  static const regex sql_comment_pattern(R"(((?:^|\s)--\s+.*)|(?:^|[\s;])\/\*[\s\S]*?\*\/)");  // Comment
  static const regex and_or_pattern(R"((\b(and|or)|\|\||&&)([\s\+]+|\*.*?\*|['"(])+(\w|\s)*([\s\+]|['")])*(?:!=|>=|<=|=|>|<|like)+)"); // AND OR
  static const regex order_by_pattern(R"(['")\s\+]*\b(order|ororderder)\b[\s\+]*\bby\b[\s\+]*\d+[\s\+]*\/\*)"); // Order By
  static const regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
  static const regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function

  // Broken Access Control
  static regex path_traversal_pattern(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
  static regex lfi_pattern(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");