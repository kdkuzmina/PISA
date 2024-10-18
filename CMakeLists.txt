cmake_minimum_required(VERSION 3.21)
project(CryptoApp)

# Устанавливаем стандарт C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Включаем автоматическую обработку moc
set(CMAKE_AUTOMOC ON)

# Поддержка macOS, Linux и Windows
if (APPLE)
    set(CMAKE_PREFIX_PATH "/usr/local/opt/qt/lib/cmake")
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
    set(OPENSSL_LIBRARIES "/usr/local/opt/openssl/lib")
    set(OPENSSL_INCLUDE_DIR "/usr/local/opt/openssl/include")
    find_package(Qt6 REQUIRED COMPONENTS Widgets)
elseif (UNIX AND NOT APPLE)
    find_package(Qt5Widgets REQUIRED)
    find_package(OpenSSL REQUIRED)
else()
    set(CMAKE_PREFIX_PATH "C:/Qt/5.15.2/mingw81_64/lib/cmake/Qt5") # Windows (MinGW или MSVC)
    set(OPENSSL_ROOT_DIR "C:/OpenSSL-Win64")
    set(OPENSSL_LIBRARIES "C:/OpenSSL-Win64/lib")
    set(OPENSSL_INCLUDE_DIR "C:/OpenSSL-Win64/include")
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets) # Измените на Qt5, если используете Qt5
find_package(OpenSSL REQUIRED)

# Источники проекта
set(SOURCES main.cpp)

# Создаем исполняемый файл
add_executable(CryptoApp ${SOURCES})

# Линкуем библиотеки
target_link_libraries(CryptoApp Qt6::Widgets OpenSSL::SSL OpenSSL::Crypto) # Измените на Qt5::Widgets, если используете Qt5

# Указываем пути для заголовков OpenSSL
include_directories(${OPENSSL_INCLUDE_DIRS})
