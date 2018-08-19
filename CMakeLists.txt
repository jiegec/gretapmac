cmake_minimum_required(VERSION 3.8)
project(gretapmac)

add_executable(gretapmac main.cpp)
target_compile_features(gretapmac PRIVATE cxx_std_11)
