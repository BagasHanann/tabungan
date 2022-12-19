import 'dart:convert';
import 'dart:io';

import 'package:mysql1/mysql1.dart';
import 'package:crypto/crypto.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

final _router = Router()
  ..post('/auth/register', _authRegisterHandler)
  ..post('/auth/login', _authLoginHandler)
  ..get('/transaction', _getTransaction)
  ..post('/transaction', _postTransaction)
  ..patch('/transaction', _patchTransaction)
  ..delete('/transaction', _deleteTransaction)
  ..delete('/transaction/hard-delete', _hardDeleteTransaction);

Future<MySqlConnection> _connectSql() async {
  var settings = ConnectionSettings(
      host: '127.0.0.1',
      port: 3306,
      user: 'root',
      password: null,
      db: 'tabungan');

  var conn = await MySqlConnection.connect(settings);

  return conn;
}

Future<Map> validateJWT(String token) async {
  var splitBearer = token.split(" ")[1];

  try {
    final verifyJWT = JWT.verify(splitBearer, SecretKey("tabungannn"));

    if (verifyJWT.payload.toString().contains("user")) {
      return verifyJWT.payload;
    }
  } on JWTError catch (_) {
    return {'error': true};
  }

  return {'error': true};
}

Future<Response> _authRegisterHandler(Request request) async {
  // conncet sql
  var conn = await _connectSql();

  String body = await request.readAsString();
  var data = jsonDecode(body);

  var name = data["name"];
  var email = data["email"];
  var password = data["password"];
  var encryptPassword = md5.convert(utf8.encode(password)).toString();

  var findEmail =
      await conn.query('SELECT * FROM user WHERE email = ?', [email]);

  if (findEmail.isNotEmpty) {
    return Response.unauthorized('Error: Email already exists');
  }

  await conn.query("INSERT INTO user (name, email, password) VALUES (?,?,?)",
      [name, email, encryptPassword]);

  return Response.ok("Success Create Account");
}

Future<Response> _authLoginHandler(Request request) async {
  var conn = await _connectSql();
  String body = await request.readAsString();
  var data = json.decode(body);

  var email = data["email"];
  var password = data["password"];

  var findEmail =
      await conn.query('SELECT * FROM user WHERE email = ?', [email]);

  if (findEmail.isNotEmpty) {
    var matchPassword = findEmail.first.fields["password"] ==
        md5.convert(utf8.encode(password)).toString();
    if (matchPassword) {
      final payload = JWT(findEmail.first.fields);
      var token = payload.sign(SecretKey('tabungannn'));

      var user = {"user": findEmail.first.fields, "jwt": token};
      return Response.ok(user.toString());
    }

    return Response.unauthorized("Error: Wrong password");
  }

  return Response.unauthorized("Error: Email not found");
}

Future<Response> _getTransaction(Request request) async {
  var token = request.headers["authorization"];
  var verifyJWT = await validateJWT(token.toString());

  if (!verifyJWT.toString().contains("user")) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await _connectSql();
  String body = await request.readAsString();
  var data = jsonDecode(body);

  var userId = verifyJWT['user']['id'];

  var withDeleted = data["with_deleted"];
  if (withDeleted) {
    var transaction = await conn.query(
        "SELECT * FROM transaction WHERE user_id=? ORDER BY id DESC", [userId]);
    return Response.ok(transaction.toString());
  }

  var transaction = await conn.query(
      "SELECT * FROM transaction WHERE user_id=? AND deleted_at IS NULL ORDER BY id DESC",
      [userId]);

  return Response.ok(transaction.toString());
}

Future<Response> _postTransaction(Request request) async {
  var token = request.headers["authorization"];
  var verifyJWT = await validateJWT(token.toString());

  if (!verifyJWT.toString().contains("user")) {
    return Response.unauthorized("Error: Unauthorized");
  }

  var conn = await _connectSql();
  String body = await request.readAsString();
  var data = jsonDecode(body);

  var title = data["title"];
  var amount = data["amount"];
  var status = data["status"];
  var userId = verifyJWT['user']['id'];
  var timestamp = DateTime.now().toString();

  await conn.query(
      "INSERT INTO transaction (title, amount, status, input_date, update_date, user_id) VALUES (?,?,?,?,?,?)",
      [title, amount, status, timestamp, timestamp, userId]);

  return Response.ok("Add transaction success");
}

Future<Response> _patchTransaction(Request request) async {
  var token = request.headers["authorization"];
  var verifyJWT = await validateJWT(token.toString());

  if (!verifyJWT.toString().contains("user")) {
    return Response.unauthorized("Error: Unauthorized");
  }

  // call mysql
  var conn = await _connectSql();
  String body = await request.readAsString();
  var data = jsonDecode(body);

  var id = data["id"];
  var title = data["title"];
  var amount = data["amount"];
  var status = data["status"];
  var userID = verifyJWT['user']['id'];
  var timestamp = DateTime.now().toString();

  var findTransaction = await conn.query(
      "SELECT * FROM transaction WHERE id=? AND user_id=?", [id, userID]);
  if (findTransaction.isEmpty) {
    return Response.notFound("Error: transaction Not Found");
  }

  await conn.query(
      "UPDATE transaction SET title=?, amount=?, status=?, input_date=?, update_date=? WHERE id=? AND user_id=?",
      [title, amount, status, timestamp, timestamp, id, userID]);

  return Response.ok("Update transaction success");
}

Future<Response> _deleteTransaction(Request request) async {
  var token = request.headers["authorization"];
  var verifyJWT = await validateJWT(token.toString());
  if (!verifyJWT.toString().contains("user")) {
    return Response.unauthorized("Error: Unauthorized");
  }

  // mysql connection
  var conn = await _connectSql();
  String body = await request.readAsString();
  var data = jsonDecode(body);

  var id = data["id"];
  var timestamp = DateTime.now().toString();
  var userID = verifyJWT['user']['id'];

  var findTransaction = await conn.query(
      "SELECT * FROM transaction WHERE id=? AND user_id=?", [id, userID]);
  if (findTransaction.isEmpty) {
    return Response.notFound("Error: transaction Not Found");
  }

  await conn.query(
      "UPDATE transaction SET deleted_at=? WHERE id=? AND user_id=?",
      [timestamp, id, userID]);

  return Response.ok("Delete transaction Success");
}

Future<Response> _hardDeleteTransaction(Request request) async {
  var token = request.headers["authorization"];
  var verifyJWT = await validateJWT(token.toString());
  if (!verifyJWT.toString().contains("user")) {
    return Response.unauthorized("Error: Unauthorized");
  }

  // mysql connection
  var conn = await _connectSql();
  String body = await request.readAsString();
  var data = jsonDecode(body);

  var id = data["id"];
  var userID = verifyJWT['user']['id'];

  var findTransaction = await conn.query(
      "SELECT * FROM transaction WHERE id=? AND user_id=?", [id, userID]);
  if (findTransaction.isEmpty) {
    return Response.notFound("Error: Transaction Not Found");
  }

  await conn
      .query("DELETE FROM transaction WHERE id=? AND user_id=?", [id, userID]);

  return Response.ok("Delete transaction Success");
}

void main(List<String> args) async {
  // Use any available host or container IP (usually `0.0.0.0`).
  final ip = InternetAddress.anyIPv4;

  // Configure a pipeline that logs requests.
  final _handler = Pipeline().addMiddleware(logRequests()).addHandler(_router);

  // For running in containers, we respect the PORT environment variable.
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await serve(_handler, ip, port);
  print('Server listening on port ${server.port}');
}
