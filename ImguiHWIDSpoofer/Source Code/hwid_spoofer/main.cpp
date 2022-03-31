#include "gui.h"
#include <chrono>
#include <thread>
#include <WinBase.h>]
#pragma warning (disable :: 28251)
using namespace std;

int __stdcall wWinMain(
	HINSTANCE instance,
	HINSTANCE previousInstance,
	PWSTR arguments,
	int commandShow)
{
	// gui
	gui::CreateHWindow("Spoofer");
	gui::CreateDevice();
	gui::CreateImGui();

	while (gui::isRunning)
	{
		gui::BeginRender();
		gui::Render();
		gui::EndRender();

		std::this_thread::sleep_for(std::chrono::milliseconds(15));
	}

	// destroy gui
	gui::DestroyImGui();
	gui::DestroyDevice();
	gui::DestroyHWindow();
	return EXIT_SUCCESS;
}
