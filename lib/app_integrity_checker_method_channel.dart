import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'app_integrity_checker_platform_interface.dart';

/// An implementation of [AppIntegrityCheckerPlatform] that uses method channels.
class MethodChannelAppIntegrityChecker extends AppIntegrityCheckerPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('com.emrys.aic/epic');

  @override
  Future<String?> getchecksum() async {
    final checksum = await methodChannel.invokeMethod<String>('getchecksum');

    if (checksum != null) {
      return checksum.trim();
    } else {
      return "";
    }
  }

  @override
  Future<List<String>?> getsignature() async {
    final checksum = await methodChannel.invokeMethod<List>('getsig');
    if (checksum != null) {
      return checksum.whereType<String>().map((e) => e.trim()).toList();
    } else {
      return [];
    }
  }
}
