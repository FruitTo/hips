  // XSS Patterns
  static const regex script_injection_pattern(
    "<\\s*script[^>]*>"               // <script ...>
    "|<\\s*/\\s*script\\s*>"          // </script>
    "|%(3c|3C)\\s*script"             // %3cscript (URL-encoded)
    "|<\\s*\\w+\\s+<\\s*script"       // <tag <script  (split evasion)
    "|<\\s*/\\s*\\w+\\s+<\\s*script"  // </tag <script
    "|<\\s*\\w+\\s+</\\s*script"     // <tag </script
  );
  static const regex protocol_injection_pattern(
    "(javascript|vbscript|data)\\s*:"        // javascript: / vbscript: / data:
    "|href\\s*=\\s*[\"']?\\s*java\\s*[:&]"   // href="java: หรือ java&colon;
  );
  static const regex css_xss_pattern(
    "x?\\s*expression\\s*\\("                           // expression( / xpression(
    "|/\\s*x\\s*pression\\s*\\("                        // /xpression( (split evasion)
    "|style\\s*=.*(font-family|expression)[^;]*['\"(]"  // style= ที่มี expression
    "|url\\s*\\(\\s*javascript:"                        // url(javascript:
    "|behavior\\s*:"                                    // behavior: (IE)
    "|moz-binding\\s*:"                                 // -moz-binding: (Firefox)
  );
  static const regex event_injection_pattern(
    "\\bon(load|error|click|mouseover|mouseout|focus|blur|submit"
    "|change|input|keydown|keyup|keypress|dblclick|drag|drop|scroll"
    "|touchstart|touchend|animationstart|transitionend)\\s*="  // onXXX=
    "|%(6f|6F)(6e|6E)(4c|6c)(4F|6f)(41|61)(44|64)(%3d|=)"   // %6f%6e%6c%6f%61%64= (onload)
  );
  static const regex js_execution_pattern(
    "\\b(alert|prompt|confirm|eval|setTimeout|setInterval"
    "|Function|document\\.write|innerHTML|outerHTML|execScript)\\s*\\(" // dangerous functions
    "|\\b(document\\.cookie|document\\.domain"
    "|window\\.location|document\\.location|window\\.name)\\b"          // DOM access
    "|alert\\s*;\\s*pg\\s*\\("                                          // obfuscated alert;pg(
  );
  static const regex dangerous_tag_pattern(
    "<\\s*(img|iframe|svg|object|embed|video|audio|body|input|marquee"
    "|isindex|form|button|select|textarea|table|div|span|a|font|center"
    "|applet|frameset|frame|layer|style|base|link|meta)"
  );
  static const regex obfuscation_pattern(
    "String\\.fromCharCode"             // String.fromCharCode(...)
    "|\\\\x[0-9a-fA-F]{2}"             // \x41
    "|\\\\u[0-9a-fA-F]{4}"             // \u0041
    "|&#[0-9]+;"                        // &#65;
    "|&#x[0-9a-fA-F]+;"                // &#x41;
    "|x-imap4-modified-utf7.*(script|alert|java)"  // IMAP4 UTF-7 bypass
  );

  // SQL
  static const regex sql_comment_pattern(R"(((?:^|\s)--\s+.*)|(?:^|[\s;])\/\*[\s\S]*?\*\/)");  // Comment
  static const regex and_or_pattern(R"((\b(and|or)|\|\||&&)([\s\+]+|\*.*?\*|['"(])+(\w|\s)*([\s\+]|['")])*(?:!=|>=|<=|=|>|<|like)+)"); // AND OR
  static const regex order_by_pattern(R"(['")\s\+]*\b(order|ororderder)\b[\s\+]*\bby\b[\s\+]*\d+[\s\+]*\/\*)"); // Order By
  static const regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
  static const regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function

  // Broken Access Control
  static regex path_traversal_pattern(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
  static regex lfi_pattern(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");

  static const regex path_traversal_pattern(
    R"((\.\.(\/|\\))+|etc\/(passwd|shadow|hosts))"
  );
  static const regex lfi_pattern(
    R"((etc\/(passwd|shadow|hosts|group|issue)|[c-z]:\\|boot\.ini|win\.ini|\.htaccess|cmd\.exe|global\.asa|desktop\.ini|bin\/(cat|id|ls|sh|bash)))"
  );