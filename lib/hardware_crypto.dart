
import 'hardware_crypto_platform_interface.dart';

class HardwareCrypto {
  Future<String?> getPlatformVersion() {
    return HardwareCryptoPlatform.instance.getPlatformVersion();
  }
}
