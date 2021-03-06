package org.apache.jsp;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;

public final class des_jsp extends org.apache.jasper.runtime.HttpJspBase
    implements org.apache.jasper.runtime.JspSourceDependent {

  private static final JspFactory _jspxFactory = JspFactory.getDefaultFactory();

  private static java.util.List _jspx_dependants;

  private javax.el.ExpressionFactory _el_expressionfactory;
  private org.apache.AnnotationProcessor _jsp_annotationprocessor;

  public Object getDependants() {
    return _jspx_dependants;
  }

  public void _jspInit() {
    _el_expressionfactory = _jspxFactory.getJspApplicationContext(getServletConfig().getServletContext()).getExpressionFactory();
    _jsp_annotationprocessor = (org.apache.AnnotationProcessor) getServletConfig().getServletContext().getAttribute(org.apache.AnnotationProcessor.class.getName());
  }

  public void _jspDestroy() {
  }

  public void _jspService(HttpServletRequest request, HttpServletResponse response)
        throws java.io.IOException, ServletException {

    PageContext pageContext = null;
    HttpSession session = null;
    ServletContext application = null;
    ServletConfig config = null;
    JspWriter out = null;
    Object page = this;
    JspWriter _jspx_out = null;
    PageContext _jspx_page_context = null;


    try {
      response.setContentType("text/html; charset=UTF-8");
      pageContext = _jspxFactory.getPageContext(this, request, response,
      			null, true, 8192, true);
      _jspx_page_context = pageContext;
      application = pageContext.getServletContext();
      config = pageContext.getServletConfig();
      session = pageContext.getSession();
      out = pageContext.getOut();
      _jspx_out = out;

      out.write("\r\n");
      out.write("<html>\r\n");
      out.write("<head>\r\n");
      out.write("    <meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\r\n");
      out.write("    <title>DES算法</title>\r\n");
      out.write("    <script src=\"/js/jquery.min.js\"></script>\r\n");
      out.write("    <script src=\"/js/tripledes.js\"></script>\r\n");
      out.write("    <script src=\"/js/mode-ecb-min.js\"></script>\r\n");
      out.write("    <script>\r\n");
      out.write("\t    function uuid() {\r\n");
      out.write("\t\t\tvar s = [];\r\n");
      out.write("\t\t\tvar hexDigits = \"0123456789abcdef\";\r\n");
      out.write("\t\t\tfor (var i = 0; i < 36; i++) {\r\n");
      out.write("\t\t\t  \ts[i] = hexDigits.substr(Math.floor(Math.random() * 0x10), 1);\r\n");
      out.write("\t\t\t}\r\n");
      out.write("\t\t\ts[14] = \"4\"; // bits 12-15 of the time_hi_and_version field to 0010\r\n");
      out.write("\t\t\ts[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1); // bits 6-7 of the clock_seq_hi_and_reserved to 01\r\n");
      out.write("\t\t\ts[8] = s[13] = s[18] = s[23] = \"-\";\r\n");
      out.write("\t\t\t\r\n");
      out.write("\t\t\tvar uuid = s.join(\"\");\r\n");
      out.write("\t\t\treturn uuid;\r\n");
      out.write("    \t}\r\n");
      out.write("        /*\r\n");
      out.write("         * 加密函数\r\n");
      out.write("         * message - 要加密的源数据\r\n");
      out.write("         * key - 密钥\r\n");
      out.write("         */\r\n");
      out.write("        function encryptByDES(message, key) {\r\n");
      out.write("\t\t\t// 解析密钥， 将密钥转换成16进制数据。 就是解析为字节数据。\r\n");
      out.write("            var keyHex = CryptoJS.enc.Utf8.parse(key);\r\n");
      out.write("\t\t\t// 创建DES加密工具。 构建器。\r\n");
      out.write("            var encrypted = CryptoJS.DES.encrypt(message, keyHex, {\r\n");
      out.write("                mode: CryptoJS.mode.ECB, // 加密的模式， ECB加密模式。\r\n");
      out.write("                padding: CryptoJS.pad.Pkcs7 // 加密的padding\r\n");
      out.write("            });\r\n");
      out.write("            return encrypted.toString(); // 加密，并获取加密后的密文数据。\r\n");
      out.write("        }\r\n");
      out.write("\t\t\r\n");
      out.write("        /*\r\n");
      out.write("         * 解密函数\r\n");
      out.write("         * ciphertext - 要解密的密文数据。\r\n");
      out.write("         * key - 密钥\r\n");
      out.write("         */\r\n");
      out.write("        function decryptByDES(ciphertext, key) {\r\n");
      out.write("\r\n");
      out.write("            var keyHex = CryptoJS.enc.Utf8.parse(key);\r\n");
      out.write("            // 创建解密工具\r\n");
      out.write("            var decrypted = CryptoJS.DES.decrypt({\r\n");
      out.write("                ciphertext: CryptoJS.enc.Base64.parse(ciphertext) // 将密文数据解析为可解密的字节数据。\r\n");
      out.write("            }, keyHex, {\r\n");
      out.write("                mode: CryptoJS.mode.ECB,\r\n");
      out.write("                padding: CryptoJS.pad.Pkcs7\r\n");
      out.write("            });\r\n");
      out.write("            return decrypted.toString(CryptoJS.enc.Utf8); // 解密过程，并返回明文。\r\n");
      out.write("        }\r\n");
      out.write("\r\n");
      out.write("        function doPost(){\r\n");
      out.write("        \tvar name = $(\"#nameText\").val();\r\n");
      out.write("        \tvar password = $(\"#passwordText\").val();\r\n");
      out.write("        \tvar message = name + password;\r\n");
      out.write("        \tvar key = uuid();\r\n");
      out.write("        \tvar param = {};\r\n");
      out.write("        \tparam.name=name;\r\n");
      out.write("        \tparam.password=password;\r\n");
      out.write("        \tparam.key=key;\r\n");
      out.write("        \t// 正确的加密\r\n");
      out.write("        \tparam.message = encryptByDES(message, key);\r\n");
      out.write("        \t// 测试解密错误，如：请求拦截。\r\n");
      out.write("        \t// param.message = \"WrongSecurityMessage00\";\r\n");
      out.write("        \t// 测试异常情况。DES加密后的密文数据长度一定是8的整数倍。\r\n");
      out.write("        \t// param.message = \"testException\";\r\n");
      out.write("        \t$.ajax({\r\n");
      out.write("        \t\t'url':'/testDes',\r\n");
      out.write("        \t\t'data':param,\r\n");
      out.write("        \t\t'success':function(data){\r\n");
      out.write("        \t\t\tif(data){\r\n");
      out.write("        \t\t\t\talert(\"密文：\"+data.securityMessage+\"；key：\"+data.key);\r\n");
      out.write("        \t\t\t\tvar respMsg = decryptByDES(data.securityMessage, data.key);\r\n");
      out.write("        \t\t\t\talert(respMsg);\r\n");
      out.write("        \t\t\t}else{\r\n");
      out.write("        \t\t\t\talert(\"服务器忙请稍后重试!\");\r\n");
      out.write("        \t\t\t}\r\n");
      out.write("        \t\t}\r\n");
      out.write("        \t});\r\n");
      out.write("        }\r\n");
      out.write("\r\n");
      out.write("    </script>\r\n");
      out.write("</head>\r\n");
      out.write("\r\n");
      out.write("<body>\r\n");
      out.write("\t<center>\r\n");
      out.write("\t\t<table>\r\n");
      out.write("\t\t\t<caption>DES安全测试</caption>\r\n");
      out.write("\t\t\t<tr>\r\n");
      out.write("\t\t\t\t<td style=\"text-align: right; padding-right: 5px\">\r\n");
      out.write("\t\t\t\t\t姓名：\r\n");
      out.write("\t\t\t\t</td>\r\n");
      out.write("\t\t\t\t<td style=\"text-align: left; padding-left: 5px\">\r\n");
      out.write("\t\t\t\t\t<input type=\"text\" name=\"name\" id=\"nameText\"/>\r\n");
      out.write("\t\t\t\t</td>\r\n");
      out.write("\t\t\t</tr>\r\n");
      out.write("\t\t\t<tr>\r\n");
      out.write("\t\t\t\t<td style=\"text-align: right; padding-right: 5px\">\r\n");
      out.write("\t\t\t\t\t密码：\r\n");
      out.write("\t\t\t\t</td>\r\n");
      out.write("\t\t\t\t<td style=\"text-align: left; padding-left: 5px\">\r\n");
      out.write("\t\t\t\t\t<input type=\"text\" name=\"password\" id=\"passwordText\"/>\r\n");
      out.write("\t\t\t\t</td>\r\n");
      out.write("\t\t\t</tr>\r\n");
      out.write("\t\t\t<tr>\r\n");
      out.write("\t\t\t\t<td style=\"text-align: right; padding-right: 5px\" colspan=\"2\">\r\n");
      out.write("\t\t\t\t\t<input type=\"button\" value=\"测试\" onclick=\"doPost();\" />\r\n");
      out.write("\t\t\t\t</td>\r\n");
      out.write("\t\t\t</tr>\r\n");
      out.write("\t\t</table>\r\n");
      out.write("\t</center>\r\n");
      out.write("</body>\r\n");
      out.write("</html>");
    } catch (Throwable t) {
      if (!(t instanceof SkipPageException)){
        out = _jspx_out;
        if (out != null && out.getBufferSize() != 0)
          try { out.clearBuffer(); } catch (java.io.IOException e) {}
        if (_jspx_page_context != null) _jspx_page_context.handlePageException(t);
      }
    } finally {
      _jspxFactory.releasePageContext(_jspx_page_context);
    }
  }
}
