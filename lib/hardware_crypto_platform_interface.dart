import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'hardware_crypto_method_channel.dart';

abstract class HardwareCryptoPlatform extends PlatformInterface {
  /// Constructs a HardwareCryptoPlatform.
  HardwareCryptoPlatform() : super(token: _token);

  static final Object _token = Object();

  static HardwareCryptoPlatform _instance = MethodChannelHardwareCrypto();

  /// The default instance of [HardwareCryptoPlatform] to use.
  ///
  /// Defaults to [MethodChannelHardwareCrypto].
  static HardwareCryptoPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [HardwareCryptoPlatform] when
  /// they register themselves.
  static set instance(HardwareCryptoPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
