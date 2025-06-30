#include <crow.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <sqlite3.h>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <fstream>

// Ассоциативный контейнер для WEB-Socket соединений
// WEB-sockets, ip-address
std::unordered_map<crow::websocket::connection*, std::string> parameters_ws_active_connections;
//---------------------------------------------------------------------------------------------

namespace fs = std::filesystem;

// Функция для получения списка путей фотогалереи (рекурсивный обход каталогов)
std::vector<std::string> getAllFiles(const std::string& relativeDir) {
    std::vector<std::string> filePaths;

    try {
        // Получаем абсолютный путь к корню программы
        fs::path rootPath = fs::current_path();

        // Собираем полный путь к целевой директории
        fs::path targetPath = rootPath.string() + relativeDir;

        // Проверяем, что директория существует
        if (!fs::exists(targetPath) || !fs::is_directory(targetPath)) {
            throw std::runtime_error("Директория не существует: " + targetPath.string());
        }

        // Рекурсивный обход
        for (const auto& entry : fs::recursive_directory_iterator(targetPath)) {
            if (entry.is_regular_file()) {
                fs::path relPath = fs::relative(entry.path(), rootPath);
                filePaths.push_back(relPath.string());
            }
        }

    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return filePaths;
}

// Функция для получения списка файлов в одной папке (обычный итератор внутри одной директории)
std::vector<std::string> getAllFilesFromDir(const std::string& relativeDir) {
    std::vector<std::string> filePaths;

    try {
        // Получаем абсолютный путь к корню программы
        fs::path rootPath = fs::current_path();

        // Собираем полный путь к целевой директории
        fs::path targetPath = rootPath.string() + relativeDir;

        // Проверяем, что директория существует
        if (!fs::exists(targetPath) || !fs::is_directory(targetPath)) {
            throw std::runtime_error("Директория не существует: " + targetPath.string());
        }

        // Рекурсивный обход
        for (const auto& entry : fs::directory_iterator(targetPath)) {
            if (entry.is_regular_file()) {
                fs::path relPath = fs::relative(entry.path(), rootPath);
                filePaths.push_back(relPath.string());
            }
        }

    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return filePaths;
}

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
// Фунция для получения токена из Cookie
std::string get_session_token_from_cookie(const crow::request& req) {

    std::string cookie_header = req.get_header_value("Cookie");

    size_t token_start = cookie_header.find("session_token=");
    if (token_start == std::string::npos) {
        return "";
    }

    token_start += 14;
    size_t token_end = cookie_header.find(';', token_start);

    if (token_end == std::string::npos) {
        return cookie_header.substr(token_start);
    } else {
        return cookie_header.substr(token_start, token_end - token_start);
    }
}

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//std::string split-функция

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);

    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
// Логгирование
// Класс наследник логгера из библиотеки Crow
// По умолчанию размер файла - 1 мб, создается 5 лог-файлов (далее удаляется самый старый файл)
// файл server.0.log - самый новый)

class CustomLogger : public crow::ILogHandler
{
public:
    CustomLogger(const std::string& base_name = "server", size_t max_size = 1024*1024, int max_files = 5 )
        : base_name{base_name}, max_size{max_size}, max_files{max_files} {
        rotate();
    }
    ~CustomLogger(){
        current_stream.close();
    }
    void log(std::string message, crow::LogLevel level){

        //Мьютекс---------------------------------------------------
        std::lock_guard<std::mutex> lock(mutex);
        //-----------------------------------------------------------

        //Проверка размера файла-------------------------------------
        if (current_size + message.size() > max_size){
            rotate();
        }
        //-----------------------------------------------------------

        //Вывод------------------------------------------------------
        const char* levelStr = [](crow::LogLevel l) {
            switch(l) {
                case crow::LogLevel::Debug:    return "DEBUG";
                case crow::LogLevel::Info:     return "INFO";
                case crow::LogLevel::Warning:  return "WARNING";
                case crow::LogLevel::Error:    return "ERROR";
                case crow::LogLevel::Critical: return "CRITICAL";
                default:                       return "UNKNOWN";
            }
        }(level);

        // Исключение для ошибки asio::error::broken_pipe - клиент отключился
        if (message.find("asio.system:32") == std::string::npos) {
            std::cerr << "[" << levelStr << "] " << message << std::endl;
        }

        //-----------------------------------------------------------

        //Время записи------------------------------------------------
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "[%d-%m-%y %H:%M:%S]");
        //-----------------------------------------------------------

        //Запись в файл-----------------------------------------------
        if (!current_stream.is_open()){
            std::cerr << "Log file error!" << std::endl;
        }
        // Убрали ошибку, asio::error::broken_pipe - клиент отключился, из логов
        if (message.find("asio.system:32") == std::string::npos) {
            current_stream << ss.str() << message << std::endl;
            current_stream.flush();
            current_size += message.size();
        }
        //-----------------------------------------------------------
    }
private:
    void rotate(){
        if (current_stream.is_open()){
            current_stream.close();
        }

        for (int i = max_files-1; i >= 0; --i){
            std::string old_name = base_name + "." + std::to_string(i) + ".log";
            if (fs::exists(old_name)){
                if (i == max_files - 1){
                    fs::remove(old_name);
                }
                else {
                    fs::rename(old_name, base_name + "." + std::to_string(i + 1) + ".log");
                }
            }
        }

        current_stream.open(base_name + ".0.log");
        current_size = 0;
    }

    std::string base_name;
    size_t max_size;
    int max_files;
    size_t current_size;
    std::mutex mutex;
    std::ofstream current_stream;
};

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------

// Ассоциативный контейнер с активными сессиями
// user, token
std::unordered_map<std::string, std::string> active_session;

//-------------------------------------------------------------------------------------------------
// Ассоциативные контейнеры содержащие:
// 1) Пользователь + токен
// 2) Пользователь + кол-во попыток подключения
// Данный функционал отслеживает попытки подключения и закрывает доступ после определенного в коде кол-ва попыток
// Ограничение сбрасывается после истечения жизни Cookie (либо после очистки Cookie)

// user, token (Попытки подключения)
std::unordered_map<std::string, std::string> denied_sessions;
// user, counter (Попытки подключения)
std::unordered_map<std::string, int> denied_sessions_counter;
//-------------------------------------------------------------------------------------------------

// Генератор токена (для каждой сессии)
std::string generate_session_token()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    const char* hex_charts = "0123456789ABCDEF";
    std::string token(32, ' ');
    for (char& c : token){
        c = hex_charts[dis(gen)];
    }
    return token;
}

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
// ХЭШ-функционал (для работы с паролями)

std::string bytes_to_hex(const std::string& bytes)
{
    std::ostringstream oss;
    for (unsigned char c : bytes){
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }

    return oss.str();
}

std::string hex_to_bytes(const std::string& hex)
{
    std::string bytes;
    for (size_t i = 0; i < hex.length(); i += 2){
        std::string byte = hex.substr(i, 2);
        bytes.push_back(static_cast<char>(std::stoul(byte, nullptr, 16)));
    }

    return bytes;
}

std::string pbkd2_hash(const std::string& password, const std::string& salt, bool with_salt)
{
    const int iterations = 100000;
    const int key_len = 64;

    std::vector<unsigned char> hash(key_len);

    PKCS5_PBKDF2_HMAC(password.c_str(),
                      password.length(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()),
                      salt.length(),
                      iterations,
                      EVP_sha512(),
                      key_len,
                      hash.data());

    if (with_salt){
        return bytes_to_hex(std::string(hash.begin(), hash.end())) + ":" + bytes_to_hex(salt);
    }
    else {
        return bytes_to_hex(std::string(hash.begin(), hash.end()));
    }
}

std::string hash_password(const std::string& password)
{
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    std::string salt_str(salt, salt + sizeof(salt));
    return pbkd2_hash(password, salt_str, true);
}

bool verify_password(const std::string& password, const std::string& stored_hash)
{
    size_t colon_pos = stored_hash.find(':');
    if (colon_pos == std::string::npos) return false;

    std::string stored_hash_part = stored_hash.substr(0, colon_pos);
    std::string salt = stored_hash.substr(colon_pos + 1);

    std::string new_hash = pbkd2_hash(password, hex_to_bytes(salt), false);

    return stored_hash_part == new_hash;
}

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
// Ассоциативный контейнер для хранения пользователей и их атрибутов
// Ключ: имя пользователя
// Значение : вектор{ хэшированный пароль, роль, IP-адрес }
// user, password, role, ip-address
std::unordered_map<std::string, std::vector<std::string>> users;

//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
// Работа с базой данных пользователей
// SQLITE 3

// INSERT users
void insert_user_sql(const char* user, const char* pass, const char* role)
{
    sqlite3* db;
    int rc = sqlite3_open("users.db", &db);
    if (rc != SQLITE_OK){
        std::cout << "Error code: " << rc << std::endl;
        return;
    }

    int retries = 3;
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "INSERT INTO users (username, password, role) VALUES (?, ?, ?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pass, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, role, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE){
        while (retries > 0){
            sqlite3_step(stmt);
            retries--;
        }
    }

    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

// UPDATE users
void update_user_sql(const char* old_username, std::string original_pass, const char* user, const char* pass, const char* role)
{
    sqlite3* db;
    int rc = sqlite3_open("users.db", &db);
    if (rc != SQLITE_OK){
        std::cout << "Error code: " << rc << std::endl;
        return;
    }

    int retries = 3;
    sqlite3_stmt* stmt;
    if (original_pass != ""){
        sqlite3_prepare_v2(db, "UPDATE users SET username = ?, password = ?, role = ? WHERE username = ?;", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, pass, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, role, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, old_username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE){
            while (retries > 0){
                sqlite3_step(stmt);
                retries--;
            }
        }
    }
    else {
        sqlite3_prepare_v2(db, "UPDATE users SET username = ?, role = ? WHERE username = ?;", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, role, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, old_username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE){
            while (retries > 0){
                sqlite3_step(stmt);
                retries--;
            }
        }
    }

    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

// DELETE users
void delete_user_sql(std::string user)
{
    sqlite3* db;
    int rc = sqlite3_open("users.db", &db);
    if (rc != SQLITE_OK){
        std::cout << "Error code: " << rc << std::endl;
        return;
    }

    int retries = 3;
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "DELETE FROM users WHERE username = ?;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE){
        while (retries > 0){
            sqlite3_step(stmt);
            retries--;
        }
    }

    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

// SELECT users
void select_users_sql()
{
    users.clear();

    sqlite3* users_db;
    int rc_open = sqlite3_open("users.db", &users_db);
    if (rc_open != SQLITE_OK){
        std::cout << "Error code: " << rc_open << std::endl;
        return;
    }

    sqlite3_stmt* stmt;

    const char* sql = "SELECT * FROM users";
    if (sqlite3_prepare_v2(users_db, sql, -1, &stmt, NULL) != SQLITE_OK){
        return;
    }

    while(sqlite3_step(stmt) == SQLITE_ROW){
        std::vector<std::string> tmp;
        tmp.push_back("");//password
        tmp.push_back("");//role
        tmp.push_back("");//ip-address (в БД не хранится)

        users[std::string((const char*)sqlite3_column_text(stmt, 1))] = tmp;
        users[std::string((const char*)sqlite3_column_text(stmt, 1))][0] = std::string((const char*)sqlite3_column_text(stmt, 2));
        users[std::string((const char*)sqlite3_column_text(stmt, 1))][1] = std::string((const char*)sqlite3_column_text(stmt, 3));
    }

    //for (const auto& [user, attr] : users){
    //    std::cout << user << ": " << attr[0] << ": " << attr[1] << std::endl;
    //}

    sqlite3_finalize(stmt);

    sqlite3_close(users_db);
}
//------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------
// Функция обновления времени
// Бесконечный цикл, работающий в отдельном потоке (задержка - 1 секунда)
void update_time()
{
    while (true){

        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);

        // Преобразуем в локальное время
        std::tm local_tm = *std::localtime(&now_time);

        // Форматируем в строку
        std::ostringstream oss;
        oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");

        for (auto [conn, ip] : parameters_ws_active_connections){
            conn->send_text(oss.str());
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

//------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------
//MAIN

int main()
{

    // Объект логгирования
    CustomLogger custom_logger;
    crow::logger::setHandler(&custom_logger);

    // Загрузка пользователей из БД
    select_users_sql();

    // Абстрактные пример списка добавленных композиций, которые будут отображаться на сервере
    std::vector<std::string> tracks_list = {
        "song.mp3",
        "song2.mp3"
    };

    // Базовая настройка сервера
    crow::SimpleApp app;
    app.bindaddr("127.0.0.1");
    app.multithreaded(); // Мультипоточность
    app.ssl_file("server.crt", "server.key"); // Ключи для работы HTTPS
    app.port(8443);

    //-------------------------------------------------------------------------------------------------------
    // Обработка WEB-Сокета (здесь добавляем соединение в контейнер для каждой загруженной страницы)
    // и удаляем нужное соединение при каждом закрытии страницы
    CROW_WEBSOCKET_ROUTE(app, "/time_ws")
            .onopen([&](crow::websocket::connection& conn){
                parameters_ws_active_connections[&conn] = conn.get_remote_ip();
            })
            .onclose([&](crow::websocket::connection& conn, const std::string&, uint16_t){
                parameters_ws_active_connections.erase(&conn);
            });

    // Работа функции в отдельном потоке, обособленно от основной программы
    std::thread(update_time).detach();

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    //АВТОРИЗАЦИЯ

    // Начальная страница (redirect на /login)
    CROW_ROUTE(app, "/")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    std::cout << "Sessions: " << active_session.size() << std::endl;
                    std::cout << "Hello " + user << std::endl;

                    auto res = crow::response(302);
                    res.set_header("Location", "/home");
                    return res;
                }
            }
        }

        auto res = crow::response(302);
        res.set_header("Location", "/login");
        return res;

    });

    // Показывает страницу ввода login/pass
    CROW_ROUTE(app, "/login")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){

                    std::cout << "Sessions: " << active_session.size() << std::endl;
                    std::cout << "Hello " + user << std::endl;

                    auto res = crow::response(302);
                    res.set_header("Location", "/home");
                    return res;
                }
            }
            for (auto [user, token] : denied_sessions){
                if (token == get_session_token_from_cookie(req)){
                    if (denied_sessions_counter[user] >= 10){
                        return crow::response(403, "Try again later");
                    }
                }
            }
        }

        auto page = crow::mustache::load("login.html");
        crow::response res(page.render());
        return res;
    });

    // Обработка POST запроса ввода login/pass
    CROW_ROUTE(app, "/auth").methods(crow::HTTPMethod::POST)([](const crow::request& req){

        auto params = req.get_body_params();

        //std::cout << params << std::endl;
        //std::cout << req.body << std::endl;

        auto username = params.get("username");
        auto password = params.get("password");

        //std::cout << username << std::endl;
        //std::cout << password << std::endl;

        if (!username || !password){
            return crow::response(400, "Bad data");
        }

        auto it = users.find(username);
        if (it != users.end() && verify_password(password, it->second[0])) {

            for (auto denied_usr = denied_sessions.begin(); denied_usr != denied_sessions.end();){
                if (it->first == denied_usr->first){
                    denied_usr = denied_sessions.erase(denied_usr);
                }
                else {
                    ++denied_usr;
                }
            }
            for (auto denied_usr = denied_sessions_counter.begin(); denied_usr != denied_sessions_counter.end();){
                if (it->first == denied_usr->first){
                    denied_usr = denied_sessions_counter.erase(denied_usr);
                }
                else {
                    ++denied_usr;
                }
            }

            std::string token = generate_session_token();
            active_session[username] = token;

            users[username][2] = req.remote_ip_address;

            auto res = crow::response(302);
            res.set_header("Location", "/home");
            res.add_header("Set-Cookie", "session_token=" + token + "; Path=/; Max-Age=3600; HttpOnly; Secure");
            return res;
        }
        else if (it != users.end() && !verify_password(password, it->second[0])) {
            // Последующие попытки подключения
            for (auto [usr, tkn] : denied_sessions) {
                if (usr == username) {
                    if (denied_sessions_counter[username] >= 10){
                        return crow::response(403, "Try again later");
                    }
                    denied_sessions_counter[username]++;
                    std::cout << usr << " TRY: " << denied_sessions_counter[username] << std::endl;
                    auto res = crow::response(302);
                    res.set_header("Location", "/login");
                    return res;
                }
            }

            // Первая попытка подключения
            std::string token = generate_session_token();
            denied_sessions[username] = token;
            denied_sessions_counter[username] = 1;

            auto res = crow::response(302);
            res.set_header("Location", "/login");
            res.add_header("Set-Cookie", "session_token=" + token + "; Path=/; Max-Age=3600; HttpOnly; Secure");
            return res;
        }
        else {
            return crow::response(403, "Denied");
        }

    });

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // ДОМАШНЯЯ СТРАНИЦА

    // Страница с контентом (для авторизованных пользователей)
    CROW_ROUTE(app, "/home")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    std::cout << "Sessions: " << active_session.size() << std::endl;
                    std::cout << "Hello " + user << std::endl;
                    crow::mustache::context ctx;
                    ctx["auth_user"] = user;
                    for (const auto& [usr, attr] : users){
                        if (usr == user){
                            if (users[user][1] == "administrator"){
                                auto page = crow::mustache::load("home_admin.html");
                                crow::response res(page.render(ctx));
                                return res;
                            }
                            else if (users[user][1] == "guest"){
                                auto page = crow::mustache::load("home_guest.html");
                                crow::response res(page.render(ctx));
                                return res;
                            }
                        }
                    }
                }
            }
        }
        return crow::response(403, "Denied");
    });

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // ВЫХОД

    // Обработка кнопки "Выйти"
    CROW_ROUTE(app, "/exit")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){

                    for (auto [usr, attr] : users){
                        if (usr == user){

                            // Деактивация WEB-сокета в случае выхода пользователя (например если сайт открыт на двух вкладках)
                            // Надо иметь ввиду, что здесь сервер ориентируется на IP-адрес, поэтому если сайт открыт в разных браузерах,
                            // и авторизованы разные пользователи - в случае выхода в одном браузере, WEB-сокет в другом браузере также
                            // остановит обновление. Нужно будет обновить страницу для его запуска.
                            // Для тестового стенда оставлено данное решение.
                            for (auto it = parameters_ws_active_connections.begin(); it != parameters_ws_active_connections.end();){
                                if (it->second == attr[2]){
                                    it = parameters_ws_active_connections.erase(it);
                                }
                                else {
                                    ++it;
                                }
                            }

                            users[user][2] = "";
                        }
                    }

                    std::cout << "Sessions: " << active_session.size() << std::endl;
                    std::cout << "Goodby " + user << std::endl;

                    active_session.erase(user);

                    auto res = crow::response(302);
                    res.set_header("Location", "/login");
                    return res;

                }
            }
        }

        return crow::response(404, "Not Found");

    });

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // АДМИНИСТРИРОВАНИЕ

    // Страница с таблицей пользователей
    CROW_ROUTE(app, "/users")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){

                    crow::mustache::context ctx;
                    std::vector<crow::mustache::context> users_ctx_vector;

                    for (const auto& [username, attr] : users){
                        crow::mustache::context  usr;
                        usr["username"] = username;
                        usr["role"] = attr[1];
                        users_ctx_vector.push_back(usr);
                    }

                    ctx["users"] = std::move(users_ctx_vector);
                    ctx["auth_user"] = user;

                    auto page = crow::mustache::load("users.html");
                    crow::response res(page.render(ctx));
                    return res;
                }
            }
        }
        return crow::response(403, "Denied");
    });

    // Удаление пользователя
    CROW_ROUTE(app, "/user/delete").methods(crow::HTTPMethod::POST)([](const crow::request& req){

        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    auto json = crow::json::load(req.body);
                    if (!json) {
                        return crow::response(400, "Bad JSON");
                    }

                    auto username = json["username"].s();
                    auto role = json["role"].s();

                    //std::cout << username << std::endl;
                    //std::cout << role << std::endl;

                    if (user != username){
                        delete_user_sql(username);
                        select_users_sql();

                        active_session.erase(username);

                        crow::json::wvalue res;
                        res["message"] = "Пользователь удален";
                        res["success"] = true;
                        return crow::response(res);
                    }
                    else {
                        crow::json::wvalue res;
                        res["message"] = "Ошибка (Вы пытаетесь удалить свою учетную запись)";
                        res["success"] = false;
                        return crow::response(res);
                    }
                }
            }
        }
        crow::json::wvalue res;
        res["message"] = "Denied";
        res["success"] = false;
        return crow::response(res);
    });

    // Добавление нового пользователя
    CROW_ROUTE(app, "/user/add").methods(crow::HTTPMethod::POST)([](const crow::request& req){

        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    auto json = crow::json::load(req.body);
                    if (!json) {
                        return crow::response(400, "Bad JSON");
                    }

                    std::string username = json["username"].s();
                    std::string password = hash_password(json["password"].s());
                    std::string role = json["role"].s();

                    for (const auto& [user, attr] : users){
                        if (username == user){
                            crow::json::wvalue res;
                            res["message"] = "Пользователь " + username + " уже существует";
                            res["success"] = false;
                            return crow::response(res);
                        }
                    }

                    //std::cout << "Добавляем пользователя----------------------------------" << std::endl;
                    //std::cout << username << std::endl;
                    //std::cout << password << std::endl;
                    //std::cout << role << std::endl;
                    //std::cout << "--------------------------------------------------------" << std::endl;

                    insert_user_sql(username.c_str(), password.c_str(), role.c_str());
                    select_users_sql();

                    crow::json::wvalue res;
                    res["message"] = "Пользователь добавлен";
                    res["success"] = true;
                    return crow::response(res);
                }
            }
        }
        crow::json::wvalue res;
        res["message"] = "Denied";
        res["success"] = false;
        return crow::response(res);
    });

    // Редактирование данных пользователя
    CROW_ROUTE(app, "/user/edit").methods(crow::HTTPMethod::POST)([](const crow::request& req){

        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    auto json = crow::json::load(req.body);
                    if (!json) {
                        return crow::response(400, "Bad JSON");
                    }

                    std::string old_username = json["old_username"].s();
                    std::string old_role = json["old_role"].s();
                    std::string username = json["username"].s();
                    std::string password = json["password"].s();
                    std::string role = json["role"].s();

                    for (const auto& [user, attr] : users){
                        if (username == user && verify_password(password, attr[0]) && attr[1] == role){
                            crow::json::wvalue res;
                            res["message"] = "Пользователь " + username + " уже существует";
                            res["success"] = false;
                            return crow::response(res);
                        }
                        else if (username == user && password == "" && attr[1] == role){
                            crow::json::wvalue res;
                            res["message"] = "Пользователь " + username + " уже существует";
                            res["success"] = false;
                            return crow::response(res);
                        }
                    }

                    //std::cout << "Редактируем пользователя----------------------------------" << std::endl;
                    //std::cout << "Старые данные: " << old_username << std::endl;
                    //std::cout << "Старые данные: " << old_role << std::endl;
                    //std::cout << "Новые данные: " << username << std::endl;
                    //std::cout << "Новые данные: " << password << std::endl;
                    //std::cout << "Новые данные: " << role << std::endl;
                    //std::cout << "----------------------------------------------------------" << std::endl;

                    std::string active_token;
                    if (req.get_header_value("Cookie") != ""){
                        for (const auto& [user, token] : active_session){
                            if (user == old_username){
                                active_token = token;
                                active_session.erase(old_username);
                                active_session[username] = active_token;
                            }
                        }
                    }

                    update_user_sql(old_username.c_str(), password, username.c_str(), hash_password(password).c_str(), role.c_str());
                    select_users_sql();

                    crow::json::wvalue res;
                    res["message"] = "Данные пользователя изменены";
                    res["success"] = true;
                    return crow::response(res);
                }
            }
        }
        crow::json::wvalue res;
        res["message"] = "Denied";
        res["success"] = false;
        return crow::response(res);
    });

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // СТРАНИЦА С АУДИОЗАПИСЯМИ

    CROW_ROUTE(app, "/audio")([](const crow::request& req) {
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    crow::mustache::context ctx;
                    ctx["auth_user"] = user;

                    std::vector<crow::json::wvalue> tracks;
                    tracks.push_back({{"title", "track_1"}, {"index", "0"}});
                    tracks.push_back({{"title", "track_2"}, {"index", "1"}});
                    ctx["tracks"] = std::move(tracks);

                    auto page = crow::mustache::load("tracks.html");
                    return crow::response(page.render(ctx));
                }
            }
        }
        return crow::response(403, "Denied");
    });

    CROW_ROUTE(app, "/audio/<int>")([&tracks_list](const crow::request& req, int index) {
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    if (index < 0 || index >= (int)tracks_list.size()){
                        return crow::response(404, "Audio file not found");
                    }

                    std::ifstream audio_file("songs/" + tracks_list[index], std::ios::binary | std::ios::ate);
                    if (!audio_file) {
                        return crow::response(404, "Audio file not found");
                    }

                    // Получаем полный размер файла
                    size_t file_size = audio_file.tellg();
                    audio_file.seekg(0, std::ios::beg);

                    // Обрабатываем Range-запросы (для перемотки)
                    crow::response resp;
                    if (req.get_header_value("Range").empty()) {
                        // Полная загрузка файла
                        resp.body.assign(std::istreambuf_iterator<char>(audio_file),
                                       std::istreambuf_iterator<char>());
                        resp.set_header("Content-Type", "audio/mpeg");
                        resp.set_header("Accept-Ranges", "bytes");
                    } else {
                        // Парсим Range-заголовок
                        std::string range = req.get_header_value("Range");
                        size_t start, end;
                        if (sscanf(range.c_str(), "bytes=%zu-%zu", &start, &end) != 2) {
                            start = 0;
                            end = file_size - 1;
                        }

                        // Устанавливаем правильные заголовки
                        resp.code = 206; // Partial Content
                        resp.set_header("Content-Type", "audio/mpeg");
                        resp.set_header("Content-Range",
                                       "bytes " + std::to_string(start) +
                                       "-" + std::to_string(end) +
                                       "/" + std::to_string(file_size));
                        resp.set_header("Accept-Ranges", "bytes");

                        // Читаем нужный фрагмент файла
                        audio_file.seekg(start);
                        char* buffer = new char[end - start + 1];
                        audio_file.read(buffer, end - start + 1);
                        resp.body = std::string(buffer, end - start + 1);
                        delete[] buffer;
                    }

                    return resp;
                }
            }
        }
        return crow::response(403, "Denied");
    });

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // СТРАНИЦА С ВИДЕОЗАПИСЯМИ

    CROW_ROUTE(app, "/video")([](const crow::request& req) {
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    crow::mustache::context ctx;

                    ctx["video_source"] = "/video/video_1.mp4";

                    ctx["auth_user"] = user;

                    std::vector<crow::json::wvalue> videos;
                    videos.push_back({{"path", "/video/video_1.mp4"}, {"title", "Video_1"}, {"duration", "2:36"}});
                    videos.push_back({{"path", "/video/video_2.mp4"}, {"title", "Video_2"}, {"duration", "0:16"}});
                    ctx["videos"] = std::move(videos);

                    auto page = crow::mustache::load("videos.html");
                    return crow::response(page.render(ctx));
                }
            }
        }
        return crow::response(403, "Denied");
    });

    CROW_ROUTE(app, "/video/<string>")([](const crow::request& req, std::string filename) {
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    std::ifstream file("videos/" + filename, std::ios::binary | std::ios::ate);
                    if (!file) return crow::response(404);

                    size_t file_size = file.tellg();
                    file.seekg(0, std::ios::beg);

                    crow::response res;
                    res.set_header("Content-Type", "video/mp4");
                    res.set_header("Accept-Ranges", "bytes");

                    // Обработка Range-запросов (для перемотки)
                    if (req.headers.count("Range")) {
                        std::string range = req.get_header_value("Range");
                        size_t start, end;

                        // Парсим "bytes=start-end"
                        if (sscanf(range.c_str(), "bytes=%zu-%zu", &start, &end) != 2) {
                            start = 0;
                            end = file_size - 1;
                        }

                        // Устанавливаем правильные заголовки
                        res.code = 206; // HTTP 206 Partial Content
                        res.set_header("Content-Range",
                                      "bytes " + std::to_string(start) +
                                      "-" + std::to_string(end) +
                                      "/" + std::to_string(file_size));

                        // Читаем нужный фрагмент
                        file.seekg(start);
                        size_t chunk_size = end - start + 1;
                        std::vector<char> buffer(chunk_size);
                        file.read(buffer.data(), chunk_size);
                        res.body = std::string(buffer.data(), file.gcount());
                    }
                    else {
                        // Полная загрузка файла (если Range не указан)
                        const size_t chunk_size = 2 * 1024 * 1024;
                        std::vector<char> buffer(chunk_size);

                        while (file.read(buffer.data(), chunk_size)) {
                            res.write(std::string(buffer.data(), file.gcount()));
                        }
                        if (file.gcount() > 0) {
                            res.write(std::string(buffer.data(), file.gcount()));
                        }
                    }

                    return res;
                }
            }
        }
        return crow::response(403, "Denied");
    });

    //-------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------
    // ФОТОГАЛЕРЕЯ

    // Маршрут для фотогалереи
    CROW_ROUTE(app, "/gallery")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    crow::mustache::context ctx;
                    ctx["auth_user"] = user;

                    std::vector<std::string> images = getAllFiles("/static/images");
                    //for (auto i : images){
                    //    std::cout << i << std::endl;
                    //}

                    // Создаем миниатюры (в реальном проекте нужно генерировать их заранее)
                    std::vector<crow::mustache::context> image_contexts;
                    for (size_t i = 0; i < images.size(); ++i) {
                        crow::mustache::context img_ctx;
                        img_ctx["full_path"] = images[i];
                        img_ctx["thumbnail_path"] = images[i];
                        img_ctx["caption"] = "Фото " + std::to_string(i + 1);
                        img_ctx["@index"] = i;
                        image_contexts.push_back(img_ctx);
                    }

                    ctx["images"] = std::move(image_contexts);
                    auto page = crow::mustache::load("gallery.html");
                    return crow::response(page.render(ctx));
                }
            }
        }
        return crow::response(403, "Denied");
    });

    // Страница загрузки файлов
    CROW_ROUTE(app, "/upload_img")([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    auto page = crow::mustache::load("upload_img.html");
                    crow::response res(page.render());
                    return res;
                }
            }
        }
        return crow::response(403, "Denied");
    });

    // Функционал загрузки изображений
    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    crow::multipart::message file_message(req);

                    int uploaded_count = 0;
                    std::vector<std::string> uploaded_files;

                    for (const auto& part : file_message.parts) {
                        try {
                            // Создаем папку для загрузки, если ее нет
                            if (!fs::exists("static/images/upload")) {
                                fs::create_directories("static/images/upload");
                            }

                            std::string filename;
                            for (auto [a, b]: part.headers){
                                for (auto [k, v]: b.params){
                                    if (k == "filename"){
                                        filename = v;
                                    }
                                }
                            }
                            std::string filepath = "static/images/upload/" + filename;

                            // Проверяем, не существует ли файл
                            if (fs::exists(filepath)) {
                                filename = std::to_string(time(nullptr)) + "_" + filename;
                                filepath = "static/images/upload/" + filename;
                            }

                            // Сохраняем файл
                            std::ofstream out(filepath, std::ios::binary);
                            out << part.body;
                            out.close();

                            uploaded_files.push_back(filename);
                            uploaded_count++;

                        } catch (...) {
                            continue;
                        }
                    }

                    crow::json::wvalue result;
                    result["uploaded_count"] = uploaded_count;
                    result["files"] = uploaded_files;

                    return crow::response{result};
                }
            }
        }
        return crow::response(403, "Denied");
    });

    CROW_ROUTE(app, "/delete_image").methods(crow::HTTPMethod::POST)([](const crow::request& req){
        if (req.get_header_value("Cookie") != ""){
            for (const auto& [user, token] : active_session){
                if (token == get_session_token_from_cookie(req)){
                    auto json = crow::json::load(req.body);
                    if (!json) {
                        return crow::response(400, "Bad JSON");
                    }

                    std::string image_path = json["image_path"].s();

                    // Удаляем файл
                    if (std::filesystem::remove(image_path)) {
                        crow::json::wvalue result;
                        result["success"] = true;
                        result["message"] = "Image deleted successfully";
                        return crow::response{result};
                    } else {
                        return crow::response(404, "File not found");
                    }
                }
            }
        }
        return crow::response(403, "Denied");
    });

    // Многопоточный запуск приложения (работа через переменную согласно документации Crow)
    auto _a = app.run_async();

    return 0;
}
