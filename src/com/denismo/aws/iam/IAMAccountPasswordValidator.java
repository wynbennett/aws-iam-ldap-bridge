/*
 * Copyright (c) 2014 Denis Mikhalkin.
 *
 * This software is provided to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.  You may obtain a copy of the
 * License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.denismo.aws.iam;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.http.client.CookieStore;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.HeaderElement;
import org.apache.http.cookie.Cookie;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.SystemDefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.*;

/**
 * User: Denis Mikhalkin
 * Date: 27/11/2014
 * Time: 6:48 PM
 */
public class IAMAccountPasswordValidator implements _IAMPasswordValidator {
    private static final Logger LOG = LoggerFactory.getLogger(IAMAccountPasswordValidator.class);
    private static final String USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36";
    @Override
    public boolean verifyIAMPassword(Entry user, String pw) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        String[] pwParts = extractMFAFromPw(pw);
        try {
            String accountNumber = user.get("accountNumber").getString();
            HashMap<String,Cookie> cookies = new HashMap<String,Cookie>();
            LOG.debug("Verifying {} {} with accessKey <hidden> and secretKey <hidden>",
                    "user", user.get("uid").getString());

            CookieStore httpCookieStore = new BasicCookieStore();
            HttpClientBuilder builder = HttpClientBuilder.create().setDefaultCookieStore(httpCookieStore);
            HttpClient client = builder.build();

            HttpPost post = new HttpPost("https://us-east-1.signin.aws.amazon.com/oauth");
            post.setHeader("User-Agent", USER_AGENT);
            post.setHeader("Referer", "https://us-east-1.signin.aws.amazon.com/oauth?client_id=arn%3Aaws%3Aiam%3A%3A015428540659%3Auser%2Fhomepage&redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fconsole%2Fhome%3Fstate%3DhashArgs%2523%26isauthcode%3Dtrue&response_type=code&state=hashArgs%23");
            post.setHeader("Origin", "https://us-east-1.signin.aws.amazon.com");
            post.setHeader("Accept-Encoding","gzip, deflate, br");
            post.setHeader("Accept-Language", "en-US,en;q=0.9");
            post.setHeader("Content-Type", "application/x-www-form-urlencoded");
            post.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8");
            post.setHeader("Upgrade-Insecure-Requests", "1");
            List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
            urlParameters.add(new BasicNameValuePair("client_id", "arn:aws:iam::015428540659:user/homepage"));
            urlParameters.add(new BasicNameValuePair("isIAMUser", "1"));
            urlParameters.add(new BasicNameValuePair("account", accountNumber));
            urlParameters.add(new BasicNameValuePair("username", user.get("uid").getString()));
            urlParameters.add(new BasicNameValuePair("password", pwParts[0]));
            urlParameters.add(new BasicNameValuePair("Action", "login"));
            urlParameters.add(new BasicNameValuePair("redirect_uri", "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true"));
            urlParameters.add(new BasicNameValuePair("forceMobileApp", ""));
            urlParameters.add(new BasicNameValuePair("forceMobileLayout", ""));
            urlParameters.add(new BasicNameValuePair("mfaLoginFailure", ""));
            urlParameters.add(new BasicNameValuePair("RemainingExpiryPeriod", ""));
            urlParameters.add(new BasicNameValuePair("mfaType", "SW"));
            urlParameters.add(new BasicNameValuePair("mfacode", pwParts[1]));
            urlParameters.add(new BasicNameValuePair("next_mfacode", ""));
            post.setEntity(new UrlEncodedFormEntity(urlParameters, Charset.forName("UTF-8")));

            HttpResponse response = client.execute(post);

            return containsHeaders(response, "aws-account-alias", "aws-creds");
        } catch (IOException e) {
            LOG.error("Exception validating password for " + user.get("uid").getString(), e);
            return false;
        } catch (RuntimeException t) {
            LOG.error("Exception validating password for " + user.get("uid").getString(), t);
            throw t;
        }
    }

    private String[] extractMFAFromPw(String pw) {
        int sepIdx = pw.lastIndexOf(',');
        if (sepIdx != -1) {
            String pass = pw.substring(0, sepIdx);
            String mfacode = pw.substring(sepIdx+1);
            return new String[]{pass, mfacode};
        }
        return new String[]{pw, ""};
    }

    private boolean containsHeaders(HttpResponse response, String... headers) {
        Header[] headerList = response.getHeaders("Set-Cookie");
        Set<String> lookup = new HashSet<String>(Arrays.asList(headers));
        for (Header header : headerList) {
            String value = header.getValue();
            if (!value.contains("=")) continue;
            String[] parts = value.split("=");
            if (parts.length < 2) continue;
            lookup.remove(parts[0]);
        }
        return lookup.isEmpty();
    }
}
