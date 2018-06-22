package routines;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

/*
 * user specification: the function's comment should contain keys as follows: 1. write about the function's comment.but
 * it must be before the "{talendTypes}" key.
 *
 * 2. {talendTypes} 's value must be talend Type, it is required . its value should be one of: String, char | Character,
 * long | Long, int | Integer, boolean | Boolean, byte | Byte, Date, double | Double, float | Float, Object, short |
 * Short
 *
 * 3. {Category} define a category for the Function. it is required. its value is user-defined .
 *
 * 4. {param} 's format is: {param} <type>[(<default value or closed list values>)] <name>[ : <comment>]
 *
 * <type> 's value should be one of: string, int, list, double, object, boolean, long, char, date. <name>'s value is the
 * Function's parameter name. the {param} is optional. so if you the Function without the parameters. the {param} don't
 * added. you can have many parameters for the Function.
 *
 * 5. {example} gives a example for the Function. it is optional.
 */
public class GeonetworkSessionManagement {
    public static final String XSRF_HEADER_NAME = "XSRF-TOKEN";
    private static final Object SESSION_ID_NAME = "JSESSIONID";

    public static String getXSRFCode(String url) {
        CookieStore cookieStore = new BasicCookieStore();
        HttpContext localContext = new BasicHttpContext();
        localContext.setAttribute(ClientContext.COOKIE_STORE, cookieStore);

        HttpPost httpPost = new HttpPost(url);

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(httpPost, localContext);) {
            HttpEntity entity = response.getEntity();
            EntityUtils.consume(entity);

            List<Cookie> cookies = cookieStore.getCookies();
            for (Cookie cookie : cookies) {
                System.out.println("Cookie: " + cookie);
                if (XSRF_HEADER_NAME.equals(cookie.getName().toUpperCase())) {
                    return cookie.getValue();
                }
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static SessionDetails gnLogin(String gnUrl, String username, String password) {
        String xsrfCode = getXSRFCode(gnUrl + "/srv/eng/info?type=me");
        String loginUrl = gnUrl + "/signin";

        if (xsrfCode.equals("")) {
            return null;
        }

        CookieStore cookieStore = new BasicCookieStore();
        HttpContext localContext = new BasicHttpContext();
        localContext.setAttribute(ClientContext.COOKIE_STORE, cookieStore);


        List<NameValuePair> nvps = new ArrayList<>();
        nvps.add(new BasicNameValuePair("username", username));
        nvps.add(new BasicNameValuePair("password", password));
        nvps.add(new BasicNameValuePair("_csrf", xsrfCode));

        HttpPost httpPost = new HttpPost(loginUrl);
        try {
            URL url = new URL(gnUrl);
            String gnHost = url.getHost();
            int gnPort = url.getPort();
            if (gnPort != url.getDefaultPort()) {
                gnHost += ":" + gnPort;
            }



            BasicClientCookie xsrfCookie = new BasicClientCookie("XSRF-TOKEN", xsrfCode);
            xsrfCookie.setDomain(gnHost);

            xsrfCookie.setPath("/");
            cookieStore.addCookie(xsrfCookie);


            httpPost.setEntity(new UrlEncodedFormEntity(nvps));
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (MalformedURLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(httpPost, localContext)) {
            System.out.println(EntityUtils.toString(response.getEntity()));
            HttpEntity entity = response.getEntity();
            EntityUtils.consume(entity);
            Header locationHeader = response.getFirstHeader("Location");
            if (locationHeader != null && locationHeader.getValue().contains("login.jsp")) {
                System.out.println("Login failed at " + loginUrl);
                return null;
            }

            SessionDetails sessionDetails = new SessionDetails();

            List<Cookie> cookies = cookieStore.getCookies();
            for (Cookie cookie : cookies) {
                System.out.println("Cookie: " + cookie);
                if (XSRF_HEADER_NAME.equals(cookie.getName().toUpperCase())) {
                    sessionDetails.setXsrfToken(cookie.getValue());
                }
                if (SESSION_ID_NAME.equals(cookie.getName().toUpperCase())) {
                    sessionDetails.setSessionId(cookie.getValue());
                }
            }
            return sessionDetails;

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }



    public static class SessionDetails {
        private final static String SESSIONID_KEY = "SESSIONID";
        private final static String XSRF_KEY = "XSRF-TOKEN";
        private String xsrfToken;
        private String sessionId;

        public SessionDetails() {

        }

        public String getXsrfToken() {
            return xsrfToken;
        }

        public void setXsrfToken(String xsrfToken) {
            this.xsrfToken = xsrfToken;
        }

        public String getSessionId() {
            return sessionId;
        }

        public void setSessionId(String sessionId) {
            this.sessionId = sessionId;
        }

        public String getCookieHeaderContent() {
            StringBuffer sb = new StringBuffer();
            boolean firstElement = true;
            if (this.sessionId != null && !this.sessionId.trim().equals("")) {
                sb.append(SESSIONID_KEY)
                        .append("=")
                        .append(this.sessionId);
                firstElement = false;
            }

            if (this.xsrfToken != null && !this.xsrfToken.trim().equals("")) {
                if (!firstElement) {
                    sb.append("; ");
                }
                sb.append(XSRF_KEY)
                        .append("=" )
                        .append(this.xsrfToken);
            }

            return sb.toString();
        }



    }




}
