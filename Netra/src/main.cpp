#include <exception>
#include <iostream>

#include "netra/config/AppConfig.hpp"
#include "netra/core/Application.hpp"

int main(int argc, char** argv) {
    try {
        const bool showStartupMenu = argc == 1;
        auto config = netra::AppConfig::load(argc, argv);
        if (config.showHelp) {
            std::cout << netra::AppConfig::helpText(config.language);
            return 0;
        }

        netra::Application app(config);
        if (config.listDevices) {
            return app.listDevices();
        }

        if (showStartupMenu) {
            return app.runInteractiveMenu();
        }

        return app.run();
    } catch (const std::exception& ex) {
        std::cerr << "netra: " << ex.what() << '\n';
        return 1;
    }
}
