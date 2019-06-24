package gds.demo;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;

import org.springframework.context.annotation.Configuration;

@Configuration
public class HostNameVerify {
	
	public HostNameVerify() {
		super();
		try {
			disableHostNameVerify();
		} catch (ServletException e) {
			e.printStackTrace();
		}
	}

	private void disableHostNameVerify() throws ServletException {
		try {

			SSLContext sc;

			// 获取 SSL 上下文
			sc = SSLContext.getInstance("SSL");

			// 创建一个空的HostnameVerifier
			HostnameVerifier hv = new HostnameVerifier() {
				public boolean verify(String urlHostName, SSLSession session) {
					return true;
				}
			};

			// 不就行证书链验证的信任管理器
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
				}

				public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
				}
			} };

			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			SSLSocketFactory sslSocketFactory = sc.getSocketFactory();

			HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
			SSLContext.setDefault(sc);
			HttpsURLConnection.setDefaultHostnameVerifier(hv);
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}   
}
