#include "Render.h"

#define PRSR_MAIN ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus

namespace Standby
{
    ImFont* RobotoDefault = nullptr;
    ImFont* RobotoVeryLarge = nullptr;
    ImFont* RobotoLarge = nullptr;
    ImFont* RobotoSmall = nullptr;

    bool ProcessChanged = false;

	VOID Render()
	{
        static ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->Pos, true, ImVec2(0, 0));
        ImGui::SetNextWindowSize(viewport->Size);

        ImGui::Begin("Main Area", NULL, PRSR_MAIN);

        if (ImGui::BeginTable("##Table", 2, ImGuiTableFlags_NoSavedSettings))
        {
            ImGui::TableSetupColumn("##Table_Setup", ImGuiTableColumnFlags_WidthFixed, viewport->Size.x / 2);

            ImGui::TableNextColumn();

            ImGui::BeginGroup();

            ImDrawList* pImDraw = ImGui::GetWindowDrawList();

            ImGui::PushFont(RobotoLarge);
            ImGui::Text("PROCESS:");
            ImGui::PopFont();
            ImGui::SameLine();

            // Yes.
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.07656f, 0.07656f, 0.07656f, 1.0f));
            std::string PreviewProcess = (pSelectedProcess && _stricmp(pSelectedProcess->Name.c_str(), STANDBY_NOPROCESS)) ? ("[" + std::to_string(pSelectedProcess->Pid) + "] " + pSelectedProcess->Name) : STANDBY_NOPROCESS;
            if (ImGui::Button(PreviewProcess.c_str(), ImVec2(viewport->Size.x / 2 - 115.0f, 25.0f)))
                bSelectProcess = true;
            ImGui::PopStyleColor();

            if (bSelectProcess)
            {
                ImGui::Begin("Select Process", (bool*)&bSelectProcess, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);

                if (ImGui::BeginListBox("##SelectProcess_Box"))
                {
                    for (int i = 0; i < Standby::ProcessList.size(); i++)
                    {
                        PROCESSINFORMATION& ProcessIdx = Standby::ProcessList.at(i);

                        char ProcessName[MAX_PATH] = {};
                        strcpy_s(ProcessName, MAX_PATH, ProcessIdx.Name.c_str());

                        _strlwr_s(FilterProcess, MAX_PATH);
                        _strlwr_s(ProcessName, MAX_PATH);

                        std::string ProcessNameString = ProcessName;
                        if (ProcessNameString.find(FilterProcess, 0))
                            continue;

                        std::string StringIdx = "[" + std::to_string(ProcessIdx.Pid) + "] " + ProcessIdx.Name;

                        if (ImGui::Selectable(StringIdx.c_str(), pSelectedProcess == &ProcessIdx))
                        {
                            pSelectedProcess = &ProcessIdx;
                            Pid = pSelectedProcess->Pid;
                        }
                    }

                    ImGui::EndListBox();
                }

                ImGui::PushFont(RobotoLarge);
                ImGui::Text("PID:");
                ImGui::PopFont();

                ImGui::SameLine();

                const ImVec2 SelectProcessBoxSize = ImGui::GetItemRectSize();

                ImGui::PushItemWidth(SelectProcessBoxSize.x * 3);
                if (ImGui::InputInt("##SelectedProcessPID", (int*)&Pid, 0, 0, ImGuiInputTextFlags_EnterReturnsTrue))
                {
                    bool Found = false;
                    for (auto& ProcessIdx : ProcessList)
                    {
                        if (ProcessIdx.Pid == Pid)
                        {
                            pSelectedProcess = &ProcessIdx;
                            Found = true;
                        }
                    }

                    if (!Found)
                    {
                        Debug("[-] PID couldn't be found.");
                        Pid = 0;
                    }
                }

                ImGui::SameLine();

                if (ImGui::Button("Select"))
                {
                    if (pSelectedProcess)
                        bSelectProcess_Confirm = TRUE;
                    bSelectProcess = false;
                }

                ImGui::SameLine();

                if (ImGui::Button("Cancel"))
                    bSelectProcess = false;

                ImGui::PushFont(RobotoLarge);
                ImGui::Text("Filter:");
                ImGui::PopFont();
                ImGui::SameLine();

                ImGui::PushItemWidth(SelectProcessBoxSize.x * 5);
                ImGui::InputText("##FilterProcessInput", FilterProcess, MAX_PATH);

                const ImVec2 FilterProcessInputSize = ImGui::GetItemRectSize();

                ImGui::SameLine();

                if (ImGui::Button("R", ImVec2(FilterProcessInputSize.y, FilterProcessInputSize.y)))
                    Standby::GetAllProcesses();

                ImGui::End();
            }

            if (bSelectProcess_Confirm)
            {
                ImGui::Begin("ARE YOU SURE", (bool*)&bSelectProcess_Confirm, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);
                const ImVec2 SureBoxSize = ImGui::GetItemRectSize();

                const std::string SureText = "You are about to open a handle to " + pSelectedProcess->Name + " (" + std::to_string(pSelectedProcess->Pid) + ")";
                ImGui::Text(SureText.c_str());

                const ImVec2 SureTextSize = ImGui::CalcTextSize(SureText.c_str());

                ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                if (ImGui::Button("Confirm", ImVec2(SureTextSize.x / 2, 30.0f)))
                {
                    pSelectedProcess->BaseThreadId = GetBaseThread(pSelectedProcess->Pid);
                    if (Standby::HandleRetrieve())
                    {
                        Debug("[*] Process handle retrieved successfully.");

                        BOOL Wow64Process = false;

                        IsWow64Process(ProcessHandle, &Wow64Process);
#ifdef _WIN64
                        if (Wow64Process)
#else
                        if (!Wow64Process)
#endif
                        {
                            CloseHandle(ProcessHandle);
                            Debug("[*] Old process handle closed.");
                            ProcessHandle = NULL;
                            pSelectedProcess = NULL;
                            Pid = -1;
#ifdef _WIN64
                            Debug("[*] This is a 32-bit process, use the 32-bit version of this injector.");
#else
                            Debug("[*] This is a 64-bit process, use the 64-bit version of this injector.");
#endif
                        }
                        else
                        {
                            ProcessChanged = true;
                        }
                    }
                    else
                        Debug("[*] Process handle couldn't be retrieved.");

                    bSelectProcess_Confirm = false;
                }

                ImGui::SameLine();
                if (ImGui::Button("Cancel", ImVec2(SureTextSize.x / 2, 30.0f)))
                {
                    Debug("[*] Process handle retrieval cancelled.");
                    bSelectProcess_Confirm = false;
                }

                ImGui::End();
            }

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            ImGui::BeginChild("ProcessInformationChild", ImVec2(viewport->Size.x / 2 - 10.0f, viewport->Size.y - 90.0f), true);
            const ImVec2 ProcessInformationChildSize = ImGui::GetItemRectSize();

            static PROCESSINFORMATION_DETAILED DetailedProcessInfo = {};
            if (ProcessHandle)
            {
                if (ProcessChanged)
                {
                    if (DetailedProcessInfo.BasicInfo.Pid)
                        DetailedProcessInfo.ModulesLoaded.clear();
                    DetailedProcessInfo = GetDetailedProcessInformation(*pSelectedProcess);

                    ProcessChanged = false;
                }

                if (DetailedProcessInfo.BasicInfo.Pid)
                {
                    ImGui::PushFont(RobotoLarge);
                    ImGui::Text("%s ", DetailedProcessInfo.BasicInfo.Name.c_str());
                    ImGui::PopFont();
                    ImGui::TextWrapped("(%s)", DetailedProcessInfo.Path.c_str());

                    ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                    ImGui::Separator();

                    ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                    ImGui::PushFont(RobotoSmall);
                    ImGui::TextWrapped("These values are updated once when an handle was opened, they are there to provide a basic overlook at the target process.");
                    ImGui::PopFont();

                    ImGui::Spacing(); ImGui::Spacing();

                    ImGui::PushFont(RobotoLarge);
                    ImGui::Text("Process Id: %i", DetailedProcessInfo.BasicInfo.Pid);
                    ImGui::Text("Parent Process Id: %i", DetailedProcessInfo.ParentPid);
                    ImGui::Text("Main Thread Id: %i", DetailedProcessInfo.BasicInfo.BaseThreadId);
                    ImGui::Text("Thread Count: %i", DetailedProcessInfo.ThreadCount);

                    ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                    ImGui::Text("Modules");

                    ImGui::PopFont();

                    ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                    ImGui::Separator();

                    for (int i = 0; i < DetailedProcessInfo.ModulesLoaded.size(); i++)
                    {
                        ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                        MODULEINFORMATION& IdxModule = DetailedProcessInfo.ModulesLoaded.at(i);

                        ImGui::PushFont(RobotoLarge);
                        ImGui::Text("%s", IdxModule.ModuleName.c_str());
                        ImGui::PopFont();
                        ImGui::TextWrapped("(%s)", IdxModule.ModulePath.c_str());
                        ImGui::Text("Base: 0x%X", IdxModule.ModBaseAddr);
                        ImGui::Text("Size: 0x%X", IdxModule.ModSize);

                        ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

                        ImGui::Separator();
                    }
                }
            }

            ImGui::EndChild();

            ImGui::EndGroup();

            ImGui::TableNextColumn();
            ImGui::BeginGroup();

            ImGui::BeginChild("DllsChild", ImVec2(viewport->Size.x / 2 - 75.0f, (viewport->Size.y - 125.0f) / 2), true);
            const ImVec2 DllsChildSize = ImGui::GetItemRectSize();
             
            ImGui::Text("Selected: %s", pSelectedDll ? pSelectedDll->Name.c_str() : "None");

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
            ImGui::Separator();
          

            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);

            ImGui::PushItemWidth(DllsChildSize.x - 50.0f);
            if (ImGui::BeginListBox("##InjectionChild_Debugs"))
            {
                for (int i = 0; i < Standby::DllList.size(); i++)
                {
                    DLLINFORMATION& DllIdx = Standby::DllList.at(i);

                    std::string StringIdx = DllIdx.Name;
                    if (ImGui::Selectable(StringIdx.c_str(), pSelectedDll == &DllIdx))
                        pSelectedDll = &DllIdx;
                }

                ImGui::EndListBox();
            }
            ImGui::PopItemWidth();
            ImGui::PopStyleVar();

            ImGui::EndChild();
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
            if (ImGui::Button("INSERT", ImVec2(DllsChildSize.x / 2, 30.0f)))
            {
                pSelectedDll = nullptr;
                Standby::InsertDll();
            }
            ImGui::SameLine();
            if (ImGui::Button("REMOVE", ImVec2(DllsChildSize.x / 2, 30.0f)))
            {
                for (int i = 0; i < Standby::DllList.size(); i++)
                {
                    if (pSelectedDll == &Standby::DllList.at(i))
                    {
                        pSelectedDll = nullptr;
                        DllList.erase(DllList.begin() + i);
                    }
                }
            }
            ImGui::PopStyleVar();

            ImGui::Spacing(); ImGui::Spacing();

            ImGui::BeginChild("InjectionChild", ImVec2(viewport->Size.x / 2 - 75.0f, (viewport->Size.y - 125.0f) / 2), true);
            const ImVec2 InjectionChildSize = ImGui::GetItemRectSize();

            ImGui::Text(">> Debug Console");
            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);

            ImGui::PushItemWidth(InjectionChildSize.x - 50.0f);
            if (ImGui::BeginListBox("##InjectionChild_Debugs"))
            {
                for (int i = 0; i < Standby::DebugMessages.size(); i++)
                {
                    const std::string& StringIdx = Standby::DebugMessages.at(i);

                    if (ImGui::Selectable(StringIdx.c_str()))
                        SelectedDebugMessage = StringIdx;
                }

                ImGui::EndListBox();
            }
            ImGui::PopItemWidth();
            ImGui::PopStyleVar();

            ImGui::EndChild();

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
            if (ImGui::Button("INJECT", ImVec2(InjectionChildSize.x / 2, 30.0f)))
            {
                LPVOID DllBase = nullptr;
                if (DllBase = InjectDll(), DllBase)
                {
                    Debug("[*] Injection successfull.");

                    if (UnlinkFromPeb)
                    {
                        Debug("[*] Attempting to unlink from peb.");

                        if (Dll_UnlinkFromPeb(DllBase))
                            Debug("[*] Unlinked from peb.");
                        else
                            Debug("[-] Couldn't be unlinked from peb.");
                    }

                    if (DeletePEHeader)
                    {
                        Debug("[*] Attempting to delete pe header.");

                        if (Dll_DeletePEHeader(DllBase))
                            Debug("[*] PE header deleted.");
                        else
                            Debug("[-] PE header couldn't be deleted.");
                    }
                }
                else
                    Debug("[-] Injection failed.");
            }
            ImGui::SameLine();
            if (ImGui::Button("CONFIGURE", ImVec2(InjectionChildSize.x / 2, 30.0f)))
                bConfigure = true;
            ImGui::PopStyleVar();

            ImGui::EndGroup();

            ImGui::EndTable();
        }

        if (bConfigure)
        {
            ImGui::Begin("Configure", (bool*)&bConfigure, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);

            ImGui::PushFont(RobotoLarge);
            ImGui::Text("Process");
            ImGui::PopFont();
            ImGui::Separator();

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            static const char* HandleRetrieveModes[] = { "OpenProcess", "NtOpenProcess", "NtOpenProcess (IMP)", "Hijack Handle" };
           
            ImGui::Text("Handle Retrieve");
            ImGui::Combo("##HandleRetrieveMode", &HandleRetrieveMode, HandleRetrieveModes, IM_ARRAYSIZE(HandleRetrieveModes));

            static const char* ThreadHandleRetrieveModes[] = { "OpenThread", "NtOpenThread", "NtOpenThread (IMP)" };

            ImGui::Text("Thread Handle Retrieve");
            ImGui::Combo("##ThreadHandleRetrieveMode", &ThreadHandleRetrieveMode, ThreadHandleRetrieveModes, IM_ARRAYSIZE(ThreadHandleRetrieveModes));

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            ImGui::PushFont(RobotoLarge);
            ImGui::Text("Injection");
            ImGui::PopFont();
            ImGui::Separator();

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            static const char* MappingModes[] = { "LoadLibrary", "LdrLoadDll", "Manual Mapping" };

            ImGui::Text("Mapping");
            ImGui::Combo("##MappingMode", &MappingMode, MappingModes, IM_ARRAYSIZE(MappingModes));


            static const char* AllocModes[] = { "VirtualAllocEx", "NtAllocateVirtualMemory", "NtAllocateVirtualMemory (IMP)" };

            ImGui::Text("Allocation Mode");
            ImGui::Combo("##AllocationMode", &AllocMode, AllocModes, IM_ARRAYSIZE(AllocModes));


            static const char* FreeModes[] = { "VirtualFreeEx", "NtFreeVirtualMemory", "NtFreeVirtualMemory (IMP)" };

            ImGui::Text("Free Mode");
            ImGui::Combo("##FreeMode", &FreeMode, FreeModes, IM_ARRAYSIZE(FreeModes));


            static const char* ReadModes[] = { "ReadProcessMemory", "NtReadVirtualMemory", "NtReadVirtualMemory (IMP)" };

            ImGui::Text("Read Mode");
            ImGui::Combo("##ReadMode", &ReadMode, ReadModes, IM_ARRAYSIZE(ReadModes));


            static const char* WriteModes[] = { "WriteProcessMemory", "NtWriteVirtualMemory", "NtWriteVirtualMemory (IMP)" };

            ImGui::Text("Write Mode");
            ImGui::Combo("##WriteMode", &WriteMode, WriteModes, IM_ARRAYSIZE(WriteModes));


            static const char* ProtectModes[] = { "VirtualProtectEx", "NtProtectVirtualMemory", "NtProtectVirtualMemory (IMP)" };

            ImGui::Text("Protect Mode");
            ImGui::Combo("##ProtectMode", &ProtectMode, ProtectModes, IM_ARRAYSIZE(ProtectModes));


            static const char* RemoteThreadModes[] = { "CreateRemoteThread", "NtCreateThreadEx", "NtCreateThreadEx (IMP)", "Hijack Thread" };

            ImGui::Text("Remote Thread");
            ImGui::Combo("##RemoteThreadMode", &RemoteThreadMode, RemoteThreadModes, IM_ARRAYSIZE(RemoteThreadModes));


            ImGui::Checkbox("Unlink From PEB", &UnlinkFromPeb);
            ImGui::Checkbox("Delete PE Header", &DeletePEHeader);

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            ImGui::Separator();

            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

            ImGui::Text("Dynamic Load Library (DLL) Injector");
            if (ImGui::IsItemHovered())
            {
                ImGui::Text("Click to open GitHub page");
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                    ShellExecuteA(*pMainWnd, "open", "https://github.com/paskalian/Standby", 0, 0, SW_SHOWNORMAL);
            }
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text(u8"Copyright © 2023 - Paskalian");

            ImGui::End();
        }

        ImGui::End();
	}
}