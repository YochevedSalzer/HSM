cmake_minimum_required(VERSION 3.10)

# Set the project name
project(grpc_client)


# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Protobuf and gRPC packages
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
file(GLOB SOURCES "src/*.cpp")

# Specify the path to the proto files
set(PROTO_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/encryption.proto
)

# Paths to the protoc and grpc_cpp_plugin binaries
set(PROTOC_PATH "/usr/local/bin/protoc")
set(GRPC_CPP_PLUGIN_PATH "/usr/local/bin/grpc_cpp_plugin")

# Specify output directory for generated files
set(PROTO_GEN_DIR ${CMAKE_BINARY_DIR})
# file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

# Generate C++ source files from proto files
foreach(proto_file ${PROTO_FILES})
    get_filename_component(proto_name ${proto_file} NAME_WE)

    # Protobuf C++ source files
    add_custom_command(
        OUTPUT ${PROTO_GEN_DIR}/${proto_name}.pb.cc ${PROTO_GEN_DIR}/${proto_name}.pb.h
        COMMAND ${PROTOC_PATH} --cpp_out=${PROTO_GEN_DIR} --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto ${proto_file}
        DEPENDS ${proto_file}
        COMMENT "Generating protobuf code for ${proto_file}"
    )

    # gRPC C++ source files
    add_custom_command(
        OUTPUT ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.cc ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.h
        COMMAND ${PROTOC_PATH} --grpc_out=${PROTO_GEN_DIR} --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PATH} --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto ${proto_file}
        DEPENDS ${proto_file}
        COMMENT "Generating gRPC code for ${proto_file}"
    )

    list(APPEND PROTO_SRCS ${PROTO_GEN_DIR}/${proto_name}.pb.cc ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.cc)
    list(APPEND PROTO_HDRS ${PROTO_GEN_DIR}/${proto_name}.pb.h ${PROTO_GEN_DIR}/${proto_name}.grpc.pb.h)
endforeach()

set(HSM_CLIENT_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROTO_GEN_DIR}
    ${Protobuf_INCLUDE_DIRS}
    ${GRPC_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../logger)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/build/lib
)

add_library(hsm_client_lib SHARED
    ${SOURCES}
    ../logger/logger.cpp
    ${PROTO_SRCS})

target_include_directories(hsm_client_lib
    PUBLIC
    ${HSM_CLIENT_INCLUDE_DIRS})

target_link_libraries(hsm_client_lib
    PUBLIC
    ${Protobuf_LIBRARIES}
    gRPC::grpc++)

add_executable(${PROJECT_NAME}_tests tests/client_tests.cpp )
add_executable(${PROJECT_NAME}_tests_combinations tests/client_tests_combinations.cpp)


target_link_libraries(${PROJECT_NAME}_tests
    PRIVATE
    hsm_client_lib
    GTest::gtest
    GTest::gtest_main
)
target_link_libraries(${PROJECT_NAME}_tests_combinations
    PRIVATE
    hsm_client_lib
    GTest::gtest
    GTest::gtest_main
)



# Ensure that protobuf and gRPC code generation is properly configured
add_custom_target(proto_gen ALL
    DEPENDS ${PROTO_SRCS} ${PROTO_HDRS}
    COMMENT "Generating protobuf and gRPC code"
)

# Add dependencies to ensure proper build order
add_dependencies(hsm_client_lib proto_gen)

# set the build state to debug
set(CMAKE_BUILD_TYPE Debug)

# or add specific flags if you need
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
