package com.ecomerce.ptit.util;

import jakarta.servlet.http.HttpServletRequest;

public class ClientSide {
    public static final String CLIENT_SITE_URL = "http://localhost:3000";
    //public static final String CLIENT_SITE_URL_DEPLOY = "https://shoes-shop-fe.vercel.app";
    public static final String CLIENT_SITE_URL_ORDER_HISTORY = CLIENT_SITE_URL + "/history-order";

    public static String getSiteURL(HttpServletRequest request) {
        String siteURL = request.getRequestURL().toString();
        return siteURL.replace(request.getServletPath(), "");
    }

}