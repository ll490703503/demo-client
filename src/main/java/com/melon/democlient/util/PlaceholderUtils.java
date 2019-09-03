package com.melon.democlient.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class PlaceholderUtils {

    public static final Logger logger = LoggerFactory.getLogger(PlaceholderUtils.class);

    public static final String PLACEHOLDER_PREFIX = "${";

    public static final String PLACEHOLDER_SUFFIX = "}";

    public static String resolvePlaceholders(String src, Map<String,String> parameter){

        if (src == null || parameter.isEmpty()) {

            return src;
        }
        StringBuffer stringBuffer = new StringBuffer(src);
        int startIndex = stringBuffer.indexOf(PLACEHOLDER_PREFIX);
        while (startIndex != -1) {
            int endIndex = stringBuffer.indexOf(PLACEHOLDER_SUFFIX, startIndex + PLACEHOLDER_PREFIX.length());
            if (endIndex != -1) {
                String placeholder = stringBuffer.substring(startIndex + PLACEHOLDER_PREFIX.length(), endIndex);
                int nextIndex = endIndex + PLACEHOLDER_SUFFIX.length();
                try {
                    String propVal = parameter.get(placeholder);
                    if (propVal != null) {
                        stringBuffer.replace(startIndex, endIndex + PLACEHOLDER_SUFFIX.length(), propVal);
                        nextIndex = startIndex + propVal.length();
                    } else {
                        logger.warn("Could not resolve placeholder '" + placeholder + "' in [" + src + "] ");
                    }
                } catch (Exception ex) {
                    logger.warn("Could not resolve placeholder '" + placeholder + "' in [" + src + "]: " + ex);
                }
                startIndex = stringBuffer.indexOf(PLACEHOLDER_PREFIX, nextIndex);
            } else {
                startIndex = -1;
            }
        }
        return stringBuffer.toString();
    }

}
