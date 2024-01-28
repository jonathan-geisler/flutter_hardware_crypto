import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'hardware_crypto_platform_interface.dart';

/// An implementation of [HardwareCryptoPlatform] that uses method channels.
class MethodChannelHardwareCrypto extends HardwareCryptoPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('hardware_crypto');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
