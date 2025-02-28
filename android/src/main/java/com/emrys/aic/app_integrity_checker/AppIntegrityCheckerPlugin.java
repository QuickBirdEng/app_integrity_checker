package com.emrys.aic.app_integrity_checker;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;

/** AppIntegrityCheckerPlugin */
public class AppIntegrityCheckerPlugin implements FlutterPlugin, MethodCallHandler {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private MethodChannel channel;
  private Context context;

  @Override
  public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
    context = flutterPluginBinding.getApplicationContext();
    channel = new MethodChannel(flutterPluginBinding.getBinaryMessenger(), "com.emrys.aic/epic");
    channel.setMethodCallHandler(this);
  }

  @Override
  public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
    if (call.method.equals("getchecksum")) {
      String checksum = getChecksum();
      result.success(checksum);

    }else if(call.method.equals("getsig")){
      List<String> sig = getSignature();
      result.success(sig);
    }else {
      result.notImplemented();
    }
  }

  @Override
  public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
    channel.setMethodCallHandler(null);
  }


  private String getChecksum(){

    String crc = "";

    ZipFile zf = null;
    try {
      zf = new ZipFile(context.getPackageCodePath());
      ZipEntry ze = zf.getEntry("classes.dex");

      crc = String.valueOf(ze.getCrc());

    } catch (Exception e) {
      e.printStackTrace();
      crc =  "checksumFailed";
    }


    return crc;

  }

  private List<String> getSignature() {
    List<String> currentSignatures = new ArrayList<>();
    try {

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
        if (packageInfo == null
                || packageInfo.signingInfo == null) {
          return null;
        }
        if (packageInfo.signingInfo.hasMultipleSigners()) {
          for (Signature signature : packageInfo.signingInfo.getApkContentsSigners()) {
            currentSignatures.add(signatureToSha256(signature.toByteArray()));
          }
        } else {
          for (Signature signature : packageInfo.signingInfo.getSigningCertificateHistory()) {
            currentSignatures.add(signatureToSha256(signature.toByteArray()));
          }
        }
      } else {
        @SuppressLint("PackageManagerGetSignatures")
        PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
        if (packageInfo == null
                || packageInfo.signatures == null
                || packageInfo.signatures.length == 0
                || packageInfo.signatures[0] == null) {
          return null;
        }
        for (Signature signature : packageInfo.signatures) {
          currentSignatures.add(signatureToSha256(signature.toByteArray()));
        }
      }
    } catch (PackageManager.NameNotFoundException e) {
      return null;
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
    return currentSignatures;
  }

  private String signatureToSha256(byte[] sig) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(sig);
    byte[] hashText = digest.digest();
    return bytesToHex(hashText);
  }

  private String bytesToHex(byte[] bytes) {
    char[] hexArray = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    char[] hexChars = new char[bytes.length * 2];
    int v;
    for (int j = 0; j < bytes.length; j++) {
      v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }




}
