import 'app_integrity_checker_platform_interface.dart';

class AppIntegrityChecker {
  static Future<String?> getchecksum() {
    return AppIntegrityCheckerPlatform.instance.getchecksum();
  }

  static Future<List<String>?> getsignature() {
    return AppIntegrityCheckerPlatform.instance.getsignature();
  }
}
