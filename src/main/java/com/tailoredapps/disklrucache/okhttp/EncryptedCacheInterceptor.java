package com.tailoredapps.disklrucache.okhttp;

import com.tailoredapps.disklrucache.EncryptedDiskLruCache;
import okhttp3.*;
import okio.Okio;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncryptedCacheInterceptor implements Interceptor {

    private final Charset UTF_8 = Charset.forName("UTF-8");
    private final EncryptedDiskLruCache encryptedDiskLruCache;

    public EncryptedCacheInterceptor(EncryptedDiskLruCache encryptedDiskLruCache) {
        if(encryptedDiskLruCache == null) {
            throw new IllegalArgumentException("encryptedDiskLruCache is null");
        }

        this.encryptedDiskLruCache = encryptedDiskLruCache;
    }

    public Response intercept(Interceptor.Chain chain) throws IOException {
        String url = chain.request().url().toString();
        String cacheKey = getCacheKey(url);
        EncryptedDiskLruCache.Snapshot snapshot = encryptedDiskLruCache.get(cacheKey);

        if(snapshot != null) {
            String contentType = Okio.buffer(Okio.source(snapshot.getInputStream(0))).readString(UTF_8);
            byte[] bytes = Okio.buffer(Okio.source(snapshot.getInputStream(1))).readByteArray();
            return new Response.Builder()
                .code(200)
                .message("OK")
                .protocol(Protocol.HTTP_1_1)
                .request(chain.request())
                .body(ResponseBody.create(MediaType.parse(contentType), bytes))
                .build();
        }

        EncryptedDiskLruCache.Editor editor = encryptedDiskLruCache.edit(cacheKey);

        if(editor != null) {
            Response response = chain.proceed(chain.request());

            if(response.body() != null) {
                String contentType = response.body().contentType().toString();
                byte[] bytes = response.body().bytes();

                try {
                    editor.newOutputStream(0).write(contentType.getBytes(UTF_8));
                    editor.newOutputStream(1).write(bytes);
                    editor.commit();
                } catch (Exception e) {
                    editor.abort();
                }

                return response.newBuilder().body(ResponseBody.create(null, bytes)).build();
            } else {
                return response;
            }

        }

        return chain.proceed(chain.request());
    }

    private String getCacheKey(String url) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(url.getBytes(UTF_8));
            BigInteger bigInt = new BigInteger(1, hash);
            String output = bigInt.toString(16);
            while(output.length() < 64 ) { output = "0"+output; }
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 hash algorithm not available", e);
        }
    }

}