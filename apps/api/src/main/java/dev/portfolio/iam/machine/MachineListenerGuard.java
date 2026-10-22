package dev.portfolio.iam.machine;

import java.io.IOException;
import jakarta.servlet.*;
import jakarta.servlet.http.*;

/** Runs on every dispatch, including forwards, includes, errors and async dispatches. */
public final class MachineListenerGuard implements Filter {
  static final String TRANSPORT = MachineListenerGuard.class.getName() + ".transport";
  record Transport(boolean machine) {}

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest http = (HttpServletRequest) request;
    HttpServletResponse out = (HttpServletResponse) response;
    // Includes retain the original servletPath; their target is in the include attribute.
    String path = (String) http.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
    String info;
    if (path == null) {
      path = http.getServletPath();
      info = http.getPathInfo();
    } else {
      info = (String) http.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
    }
    if (info != null) path += info;
    boolean machinePath = path.equals("/api/machine") || path.startsWith("/api/machine/");
    Object evidence = http.getAttribute(TRANSPORT);
    boolean permitted = evidence instanceof Transport transport && transport.machine() == machinePath;
    if (!permitted) {
      // An include cannot change response status: throw instead of executing its target.
      if (http.getDispatcherType() == DispatcherType.INCLUDE) throw new ServletException("Listener access denied");
      out.setStatus(HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    chain.doFilter(request, response);
  }
}
