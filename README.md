![STANDBY LOGO](Images/Logo.svg "STANDBY_LOGO")
<p align="center"><b>Configurable easy to use DLL injector powered by <a href="https://github.com/ocornut/imgui" target="_blank">Dear ImGui</a></b></p>

<br>
<p align="center">
<img src="https://github.com/paskalian/Standby/blob/master/Images/Menu.svg" alt="Menu"/>
</p>
<br>

# LEGAL NOTICE
<ins><b>I do not take responsibility for any misuse of this DLL injector in any way.</b></ins>

# Compatibility
Made to be compatible with both x64 and x86, tested on x64, **not sure about x86**.

# Usage

The Standby DLL injector consists of 4 parts;

1. Configuring (**Can be skipped in simple usage**)
2. Process selection
3. Dll selection
4. Injection

### Configuring
By clicking on configure you will be granted with a configuration window which you can change the program behaviour from. In here you can change which functions or methods will be used and which actions will be taken by the program while process selection and injection.

### Process Selection

By clicking on 'No Process Selected' you will be granted with a process selection window which you can select your target process from. After you select your process you must click Select, this will open up an confirm window - since this action will open a handle to the target process- and after confirming the program will open a handle to target process using your configurations and display basic information about it.

### Dll Selection

By clicking on insert you will be granted with a file selection window which you can select your .dll file to be used by the program, do not forget that you have to select that .dll file while injecting in the upper window.

By clicking on remove the program will delete that entry from the dll list.

### Injection

By clicking on inject the program will start to inject the dll using your configurations.
