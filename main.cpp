#include <openssl/aes.h>
#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QLabel>
#include <QProgressBar>
#include <QThread>
#include <QFile>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <QDebug>
#include <algorithm>

// Константы для шифрования
const int SALT_SIZE = 16;  /**< Размер соли для шифрования */
const int IV_SIZE = 16;    /**< Размер вектора инициализации (IV), если используется */
const int KEY_SIZE = 32;   /**< Размер ключа для AES-256 */

// Функции шифрования и дешифрования

/**
 * @brief Шифрует файл с использованием AES-256-ECB.
 * 
 * Функция генерирует случайную соль для шифрования, использует её для генерации ключа
 * на основе пароля пользователя с использованием PBKDF2, а затем шифрует файл
 * с использованием алгоритма AES-256-ECB. Зашифрованные данные записываются в файл.
 * 
 * @param filePath Путь к файлу, который нужно зашифровать.
 * @param password Пароль для генерации ключа шифрования.
 * @param parent Указатель на родительский объект (по умолчанию nullptr).
 * @return true, если шифрование прошло успешно.
 * @return false, если произошла ошибка (например, не удалось открыть файл или сгенерировать ключ).
 * 
 * @note Используется алгоритм AES-256-ECB без IV. Этот режим шифрования не обеспечивает защиту от атак на повторение блоков, поэтому рекомендуется использовать его только для простых случаев.
 */
bool encryptFile(const QString &filePath, const QString &password, QObject *parent = nullptr);

/**
 * @brief Расшифровывает файл с использованием AES-256-ECB.
 * 
 * Функция извлекает соль из зашифрованного файла, использует её для генерации ключа
 * на основе пароля пользователя с помощью PBKDF2, а затем расшифровывает данные, записанные в файл.
 * 
 * @param filePath Путь к файлу, который нужно расшифровать.
 * @param password Пароль для генерации ключа шифрования.
 * @param parent Указатель на родительский объект (по умолчанию nullptr).
 * @return true, если расшифровка прошла успешно.
 * @return false, если произошла ошибка (например, неверный пароль или повреждённые данные).
 * 
 * @note Функция использует AES-256-ECB без IV. В случае повреждённых данных или неверного пароля функция вернёт false.
 */
bool decryptFile(const QString &filePath, const QString &password, QObject *parent = nullptr);

// Класс для выполнения шифрования/дешифрования в отдельном потоке

/**
 * @brief Класс для выполнения операций шифрования или дешифрования в отдельном потоке.
 * 
 * Класс запускает функцию шифрования или дешифрования файла в зависимости от переданного режима.
 */
class CryptoWorker : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Конструктор класса CryptoWorker.
     * 
     * @param filePath Путь к файлу для шифрования/дешифрования.
     * @param password Пароль для генерации ключа шифрования.
     * @param encryptMode Указывает режим: true для шифрования, false для дешифрования.
     */
    CryptoWorker(const QString &filePath, const QString &password, bool encryptMode) 
        : filePath(filePath), password(password), encryptMode(encryptMode) {}

signals:
    /**
     * @brief Сигнал для передачи завершения операции.
     * 
     * @param success true, если операция завершена успешно.
     */
    void finished(bool success);  // Сигнал завершения операции

public slots:
    /**
     * @brief Запускает процесс шифрования или дешифрования.
     * 
     * В зависимости от режима выполняет шифрование или дешифрование файла.
     */
    void process() {
        bool result = encryptMode ? encryptFile(filePath, password, this) : decryptFile(filePath, password, this);
        emit finished(result);  // После завершения шифрования/дешифрования
    }

private:
    QString filePath;    /**< Путь к файлу для шифрования/дешифрования */
    QString password;    /**< Пароль для генерации ключа */
    bool encryptMode;    /**< Режим: true для шифрования, false для дешифрования */
};

// Основной класс приложения

/**
 * @brief Основной класс приложения с графическим интерфейсом.
 * 
 * Этот класс содержит элементы интерфейса для выбора файла, ввода пароля и запуска
 * процесса шифрования/дешифрования.
 */
class CryptoApp : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief Конструктор для создания интерфейса приложения.
     * 
     * @param parent Указатель на родительский виджет (по умолчанию nullptr).
     */
    CryptoApp(QWidget *parent = nullptr);

private slots:
    /**
     * @brief Открывает диалог для выбора файла.
     */
    void selectFile();

    /**
     * @brief Запускает процесс шифрования.
     */
    void startEncrypt();

    /**
     * @brief Запускает процесс дешифрования.
     */
    void startDecrypt();

    /**
     * @brief Обрабатывает завершение операции шифрования/дешифрования.
     * 
     * @param success true, если операция завершена успешно.
     */
    void onFinished(bool success);

private:
    QLineEdit *filePathEdit;   /**< Поле для ввода пути к файлу */
    QLineEdit *passwordEdit;   /**< Поле для ввода пароля */
    QProgressBar *progressBar; /**< Прогресс-бар для отображения выполнения */
    QThread *workerThread;     /**< Поток для выполнения шифрования/дешифрования */
};

// Определения функций шифрования и дешифрования

/**
 * @brief Шифрует файл с использованием AES-256-ECB.
 * 
 * @param filePath Путь к файлу, который нужно зашифровать.
 * @param password Пароль для генерации ключа шифрования.
 * @param parent Указатель на родительский объект (по умолчанию nullptr).
 * @return true, если шифрование прошло успешно.
 * @return false, если произошла ошибка (например, не удалось открыть файл или сгенерировать ключ).
 */
bool encryptFile(const QString &filePath, const QString &password, QObject *parent) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Ошибка открытия файла для шифрования";
        return false;
    }

    QByteArray fileData = file.readAll();
    file.close();

    // Генерация соли
    unsigned char salt[SALT_SIZE];
    RAND_bytes(salt, sizeof(salt));  // Генерация случайной соли

    // Логируем соль для отладки
    qDebug() << "Соль:" << QByteArray(reinterpret_cast<char*>(salt), SALT_SIZE).toHex();

    // Генерация ключа из пароля и соли
    unsigned char key[KEY_SIZE];
    int iterations = 10000;
    if (!PKCS5_PBKDF2_HMAC(password.toUtf8().data(), password.size(), salt, sizeof(salt), iterations, EVP_sha256(), KEY_SIZE, key)) {
        qDebug() << "Ошибка генерации ключа";
        return false;
    }

    // Логируем ключ
    qDebug() << "Ключ:" << QByteArray(reinterpret_cast<char*>(key), KEY_SIZE).toHex();

    // Инициализация шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr);  // AES-256-ECB, без IV

    QByteArray encryptedData;
    int blockSize = fileData.size() + AES_BLOCK_SIZE;  // Добавляем запас на финальный блок

    encryptedData.resize(blockSize);

    int out_len = 0, final_len = 0;
    
    // Шифрование данных
    if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(encryptedData.data()), &out_len,
                           reinterpret_cast<const unsigned char*>(fileData.data()), fileData.size())) {
        qDebug() << "Ошибка при шифровании данных";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Финальный блок
    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(encryptedData.data()) + out_len, &final_len)) {
        qDebug() << "Ошибка при завершении шифрования";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    encryptedData.resize(out_len + final_len);  // Устанавливаем финальный размер зашифрованных данных

    EVP_CIPHER_CTX_free(ctx);

    // Открытие файла для записи зашифрованных данных
    if (!file.open(QIODevice::WriteOnly)) {
        qDebug() << "Ошибка открытия файла для записи зашифрованных данных";
        return false;
    }

    // Запись соли перед зашифрованными данными
    file.write(reinterpret_cast<char*>(salt), SALT_SIZE);
    file.write(encryptedData);
    file.close();

    return true;
}

/**
 * @brief Расшифровывает файл с использованием AES-256-ECB.
 * 
 * @param filePath Путь к файлу, который нужно расшифровать.
 * @param password Пароль для генерации ключа шифрования.
 * @param parent Указатель на родительский объект (по умолчанию nullptr).
 * @return true, если расшифровка прошла успешно.
 * @return false, если произошла ошибка (например, неверный пароль или повреждённые данные).
 */
bool decryptFile(const QString &filePath, const QString &password, QObject *parent) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Ошибка открытия файла для расшифровки";
        return false;
    }

    // Чтение соли из файла
    unsigned char salt[SALT_SIZE];
    if (file.read(reinterpret_cast<char*>(salt), SALT_SIZE) != SALT_SIZE) {
        qDebug() << "Ошибка чтения соли";
        return false;
    }

    // Логируем соль для отладки
    qDebug() << "Соль (при расшифровке):" << QByteArray(reinterpret_cast<char*>(salt), SALT_SIZE).toHex();

    // Чтение зашифрованных данных
    QByteArray encryptedData = file.readAll();
    file.close();

    // Генерация ключа из пароля и соли
    unsigned char key[KEY_SIZE];
    int iterations = 10000;
    if (!PKCS5_PBKDF2_HMAC(password.toUtf8().data(), password.size(), salt, sizeof(salt), iterations, EVP_sha256(), KEY_SIZE, key)) {
        qDebug() << "Ошибка генерации ключа";
        return false;
    }

    // Логируем ключ для отладки
    qDebug() << "Ключ (при расшифровке):" << QByteArray(reinterpret_cast<char*>(key), KEY_SIZE).toHex();

    // Инициализация расшифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr);  // AES-256-ECB, без IV

    QByteArray decryptedData;
    int blockSize = encryptedData.size();  // Размер буфера для расшифрованных данных
    decryptedData.resize(blockSize);

    int out_len = 0, final_len = 0;

    // Расшифрование данных
    if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decryptedData.data()), &out_len,
                           reinterpret_cast<const unsigned char*>(encryptedData.data()), encryptedData.size())) {
        qDebug() << "Ошибка при расшифровке данных";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Финальный блок
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decryptedData.data()) + out_len, &final_len) != 1) {
        qDebug() << "Ошибка при завершении расшифровки. Неверный пароль или поврежденные данные";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    decryptedData.resize(out_len + final_len);  // Обрезаем данные до корректного размера

    EVP_CIPHER_CTX_free(ctx);

    // Открытие файла для записи расшифрованных данных
    if (!file.open(QIODevice::WriteOnly)) {
        qDebug() << "Ошибка открытия файла для записи расшифрованных данных";
        return false;
    }

    file.write(decryptedData);
    file.close();

    return true;
}

// Точка входа
/**
 * @brief Точка входа в приложение.
 * 
 * @param argc Количество аргументов командной строки.
 * @param argv Массив аргументов командной строки.
 * @return int Код завершения программы.
 */
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    CryptoApp window;
    window.setWindowTitle("CryptoApp - Шифрование/Расшифрование файлов");
    window.resize(400, 200);
    window.show();

    return app.exec();
}

#include "main.moc"
