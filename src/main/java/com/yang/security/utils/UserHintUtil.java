package com.yang.security.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yang.security.model.UserHint;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 给用户提示的信息
 * @author jevon
 */
public class UserHintUtil {

  public static void userHintInformation(HttpServletResponse response, int status, Object hint) throws IOException {
    try {
      ObjectMapper mapper = new ObjectMapper();
      response.setContentType("application/json;charset=UTF-8");
      response.setStatus(status);
      PrintWriter printWriter = response.getWriter();
      printWriter.write(mapper.writeValueAsString(hint));
    } catch (IOException e) {
      response.setContentType("text/plain;charset=UTF-8");
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      PrintWriter printWriter = response.getWriter();
      printWriter.write("error");
    }
  }

  public static void userHintInformation(HttpServletResponse response, int status, String hint) throws IOException {
    userHintInformation(response, status, new UserHint(hint));
  }

}
