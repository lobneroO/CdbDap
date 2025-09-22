cmake_minimum_required(VERSION 3.16)
project(TestProgram LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set default build type to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
endif()

# Configure compiler-specific options
if(MSVC)
    # Visual Studio/cl.exe options
    set(CMAKE_CXX_FLAGS_DEBUG "/Zi /EHsc /Od /MDd /RTC1")
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /EHsc /MD /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /Zi /EHsc /MD /DNDEBUG")
    
    # Generate debug information for all configurations
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/DEBUG")
    
    # Suppress MSVC logo (equivalent to /nologo)
    add_compile_options(/nologo)
    
else()
    # GCC/Clang options for cross-platform compatibility
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
endif()

# Define the executable target
add_executable(test_program test_program.cpp)

# Set output directory to current binary directory
set_target_properties(test_program PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    OUTPUT_NAME "test_program"
)

# Ensure debug symbols are generated for all build types on Windows
if(WIN32)
    set_target_properties(test_program PROPERTIES
        VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

# Platform-specific configurations
if(WIN32)
    # Windows-specific settings
    if(MSVC)
        # Enable parallel compilation
        target_compile_options(test_program PRIVATE /MP)
        
        # Set subsystem to console
        set_target_properties(test_program PROPERTIES
            LINK_FLAGS "/SUBSYSTEM:CONSOLE"
        )
    endif()
else()
    # Linux/Unix settings
    target_link_libraries(test_program PRIVATE pthread)
endif()

# Custom target for cleaning intermediate files
add_custom_target(clean-intermediate
    COMMAND ${CMAKE_COMMAND} -E remove -f
        ${CMAKE_CURRENT_BINARY_DIR}/test_program.obj
        ${CMAKE_CURRENT_BINARY_DIR}/test_program.ilk
    COMMENT "Cleaning intermediate files"
)

# Add dependency to clean intermediate files after build
add_custom_command(TARGET test_program POST_BUILD
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean-intermediate
    COMMENT "Cleaning up intermediate files"
    VERBATIM
)

# Print build information
message(STATUS "Building ${PROJECT_NAME}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")

# Add install target (optional)
install(TARGETS test_program
    RUNTIME DESTINATION bin
    COMPONENT Runtime
)

# Add testing support (optional)
enable_testing()
add_test(NAME run_test_program 
         COMMAND test_program
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# Custom target for running the program (equivalent to "test_program.exe")
add_custom_target(run
    COMMAND test_program
    DEPENDS test_program
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running test_program"
    VERBATIM
)

# Help target to display usage information
add_custom_target(help-usage
    COMMAND ${CMAKE_COMMAND} -E echo "Usage:"
    COMMAND ${CMAKE_COMMAND} -E echo "  cmake --build . --target test_program  # Build the program"
    COMMAND ${CMAKE_COMMAND} -E echo "  cmake --build . --target run           # Build and run the program"
    COMMAND ${CMAKE_COMMAND} -E echo "  ctest                                   # Run tests"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Debug information is automatically generated."
    COMMAND ${CMAKE_COMMAND} -E echo "Use your debugger (VS Code, Visual Studio, etc.) to debug."
    COMMENT "Displaying usage information"
)
