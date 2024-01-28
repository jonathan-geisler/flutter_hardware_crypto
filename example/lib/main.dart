import 'dart:convert';

import 'package:flutter/material.dart';

import 'package:flutter/services.dart';
import 'package:hardware_crypto/hardware_crypto.g.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class AppContent extends StatelessWidget {
  final _hardwareCryptoPlugin = HardwareCryptoApi();

  AppContent({super.key}) {
    _hardwareCryptoPlugin.generateKeyPair("test");
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: TextButton(
        onPressed: () async {
          var list = utf8.encode('Hello world!');
          var bytes = Uint8List.fromList(list);
          var blah = await _hardwareCryptoPlugin.sign("test", bytes);
          var snackBar = SnackBar(
            content: Text('Successfully signed message: signature length ${blah.length}'),
          );
          if (context.mounted) {
            ScaffoldMessenger.of(context).showSnackBar(snackBar);
          }
        },
        child: const Text('Sign with biometrics'),
      ),
    );
  }
}

class _MyAppState extends State<MyApp> {
  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: AppContent()
      ),
    );
  }
}
