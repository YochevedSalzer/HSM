cmake_minimum_required(VERSION 3.10)
# Set the project name
project(grpc_server)

# Find GMP library
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)
if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY OR NOT GMPXX_LIBRARY)
  message(FATAL_ERROR "Could not find GMP or GMPXX libraries")
endif()
include_directories(${GMP_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Protobuf and gRPC packages
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
# Gather all source files in src directory
file(GLOB SOURCES "src/*.cpp")

# Specify the path to the proto files
set(PROTO_FILES
    ${CMAKE_SOURCE_DIR}/proto/encryption.proto
)

# Paths to the protoc and grpc_cpp_plugin binaries
set(PROTOC_PATH "/usr/local/bin/protoc")
set(GRPC_CPP_PLUGIN_PATH "/usr/local/bin/grpc_cpp_plugin")

# Specify output directory for generated files
set(PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR})

# Generate C++ source files from proto files
foreach(proto_file ${PROTO_FILES})
    get_filename_component(proto_name ${proto_file} NAME_WE)
    
    # Protobuf C++ source files
    add_custom_command(
        OUTPUT ${PROTO_GEN_DIR}/${proto_name}.pb.cc ${PROTO_GEN_DIR}/${proto_name}.pb.h
        COMMAND ${PROTOC_PATH} --cpp_out=${PROTO_GEN_DIR} --proto_path=${CMAKE_SOURCE_DIR}/proto ${proto_file}
        DEPENDS ${proto_file}
        COMMENT "Generating protobuf code for ${proto_file}"
    )
    
    # gRPC C++ source files
    add_custom_command(
        OUTPUT ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.cc ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.h
        COMMAND ${PROTOC_PATH} --grpc_out=${PROTO_GEN_DIR} --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PATH} --proto_path=${CMAKE_SOURCE_DIR}/proto ${proto_file}
        DEPENDS ${proto_file}
        COMMENT "Generating gRPC code for ${proto_file}"
    )
    
    list(APPEND PROTO_SRCS ${PROTO_GEN_DIR}/${proto_name}.pb.cc ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.cc)
    list(APPEND PROTO_HDRS ${PROTO_GEN_DIR}/${proto_name}.pb.h ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.h)
endforeach()

# Include the generated files directory
include_directories(${PROTO_GEN_DIR})

# Include directories for protobuf and gRPC
include_directories(${Protobuf_INCLUDE_DIRS} ${GRPC_INCLUDE_DIRS})

# Add the logger library
file(GLOB LOGGER_SOURCES "logger/*.cpp")
add_library(logger STATIC ${LOGGER_SOURCES})

# Add the executable
add_executable(grpc_server src/my_logger.cpp ${SOURCES} ${PROTO_SRCS})

# Link against protobuf, gRPC, GMP, and logger libraries
target_link_libraries(grpc_server 
    ${Protobuf_LIBRARIES} 
    ${GMP_LIBRARY} 
    ${GMPXX_LIBRARY} 
    gRPC::grpc++ 
    logger)
# Set build type to Release for optimizations
set(CMAKE_BUILD_TYPE Release)

# Set optimization flags for Release mode
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

file(GLOB TESTS_SRCS "tests/*.cpp")
set(SOURCES_FOR_TESTS ${SOURCES})
list(REMOVE_ITEM SOURCES_FOR_TESTS "${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_service.cpp")
add_executable(grpc_server_tests 
# ${TESTS_SRCS} 
tests/crypto_api_tests.cpp
${SOURCES_FOR_TESTS}
)
add_executable(rsa_gmp
try.cpp ${SOURCES_FOR_TESTS}
)
target_link_libraries(rsa_gmp 
    ${GMP_LIBRARY} 
    ${GMPXX_LIBRARY} 
    logger
    GTest::gtest
    GTest::gtest_main
    )
# Set debug-specific flags for tests only
# target_compile_options(grpc_server_tests PRIVATE -g -O0) # Enable debugging information

target_link_libraries(grpc_server_tests 
    ${GMP_LIBRARY} 
    ${GMPXX_LIBRARY} 
    logger
    GTest::gtest
    GTest::gtest_main
    )
# Ensure that protobuf and gRPC code generation is properly configured
add_custom_target(proto_gen ALL
    DEPENDS ${PROTO_SRCS} ${PROTO_HDRS}
    COMMENT "Generating protobuf and gRPC code"
)

# Add dependencies to ensure proper build order
add_dependencies(grpc_server proto_gen)