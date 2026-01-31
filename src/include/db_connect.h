#ifndef DB_CONNECT_H
#define DB_CONNECT_H

#include <iostream>
#include <string>

using namespace std;

string db_connect()
{
  string user, password, host, port, dbname;

  cout << "Postgres User: ";
  cin >> user;

  cout << "\nPostgres Password: ";
  cin >> password;

  cout << "\nPostgres Database Name: ";
  cin >> dbname;

  cout << "\nPostgres Host: ";
  cin >> host;

  cout << "\nPostgres Port: ";
  cin >> port;
  cin.get();
  cout << endl;

  string conninfo =
      "user=" + user +
      " password=" + password +
      " host=" + host +
      " port=" + port +
      " dbname=" + dbname +
      " target_session_attrs=read-write";

  try
  {
    pqxx::connection conn(conninfo);
    if (!conn.is_open())
    {
      cerr << "Connection object exists but is not open.\n";
      return "";
    }
    cout << "Connected to DB: " << conn.dbname() << "\n";
    return conninfo;
  }
  catch (const exception &e)
  {
    cerr << e.what() << endl;
    return "";
  }
}

void log_attack_to_db(pqxx::connection &conn, const string &c_ip, int c_port, const string &s_ip, int s_port, const string &proto, const string &attack_type, const string &attack_detail, const string &response)
{
  try
  {
    pqxx::work txn(conn);
    txn.exec_params(
      "INSERT INTO attack_logs (event_time, src_addr, src_port, dst_addr, dst_port, protocol, attack_type, attack_detail, response_type) "
      "VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8)",
      c_ip, c_port, s_ip, s_port, proto, attack_type, attack_detail, response);
    txn.commit();
  }
  catch (const pqxx::sql_error &e)
  {
    cerr << "SQL Error: " << e.what() << "\nQuery: " << e.query() << endl;
  }
  catch (const exception &e)
  {
    cerr << "General Error: " << e.what() << endl;
  }
}
#endif