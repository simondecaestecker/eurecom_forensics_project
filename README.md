# DumPNG (Forensics project)

Write a tool to visualize the content of a memory dump as a PNG picture. Each pixel represents one page of physical memory, and its color represent if it is associated to the kernel, to a userspace application, or if it is not used. In this last case, maybe two different shades could be used to differentiate pages that contain only zeros from pages that contain data.

## Getting Started

We decided to develop this tool as a Volatility plugin. It has the benefit to take advantage of the numerous already existing functionalities of Volatility for memory dump analysis.

### Prerequisites

Of course, in the aim for this tool to work properly, you need to have or install Volatility and some additional Python libraries.

#### Volatility
The Volatility Framework is a completely open collection of tools,
implemented in Python for the extraction of digital artifacts from volatile memory (RAM) samples.

You will find all the information needed to download and install Volatility [here](https://github.com/volatilityfoundation/volatility/wiki/Installation).

Basically, you have to clone the GitHub repository by issuing the following command in a Terminal:
```
git clone https://github.com/volatilityfoundation/volatility.git
```

#### Python
In order for Volatility to work properly, you need to have Python 2.6 or later (but not Python 3). Moreover, the following additional Python libraries are necessary to run it:
- Pillow
- sys
- math

Ensure to have all these libraries installed on your pc (using pip is the easiest way).


#### Memory dumps
Volatility provides numerous samples of memory dumps [here](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) to perform some tests. Mainly, we used the memory samples from **Art of Memory Forensics** book available [here](https://memoryanalysis.net/#!amf/cmg5).


### Downloading the plugin
Clone the project repository on your pc:

```
git clone https://github.com/simondecaestecker/eurecom_forensics_project.git
```

or just download the Python file on your PC.


## Using the tool

### Copy the plugin into Volatility
In order to be able to use this plugin in Volatility, you must move the script file into the plugins folder in the Volatility folder. The path is the following:
```
some_path/volatility/volatility/plugins/
```

### Execute the Volatility plugin

You are now able to launch the plugin. In this purpose, issue the following command in your Terminal:

```
python vol.py -f <path_to_dump_file> --profile=<profile> memmaptest <options>

```

### Options

You can pass different parameters to the plugin:

| parameter | explanations |
|--|--|
| -K, --kernel | blablabla |


For example, you can issue the following command:
```
python vol.py -f <path_to_dump_file> --profile=<profile> memmaptest -W 1000 -F jpg -O picture_dump -K 0x804d7000
```

### If you don't know the profile
If you are not sure of the profile you should use for your dump file, you can run the *kdbgscan* on your dump file. It will allow you to determine what is the best profile for your dump.

**Caution!** It only works for Windows dumps. There is currently no way to determine what is the right profile for Linux dumps. You can find [here](https://github.com/volatilityfoundation/volatility) the list of profiles and supported OS.

## Challenges encountered
The standard partitioning of a memory is the following:

IMAGE


However, it is entirely possible that people customizes this partitioning. Thus, we must find a way to retrieve at what offset the kernel space starts.

In the aim to do that, we wanted to use Volatility. Indeed, it indicates its ability to retrieve the kernel base. This option is provided in the *kdbgscan* plugin.

However, results show inconsistencies that we could not resolve. Indeed, for an approximatively 530 MB memory dump, it indicates that the kernel base is at **0x804d7000** (hence, XX GB):

IMAGE

Therefore, the workaround we adopted is to force the user to indicate the kernel offset in parameter of the tool. More work is to be done on this matter.


## Authors

* **Simon DECAESTECKER** - *Post-Master student* - [GitHub](https://github.com/simondecaestecker)
* **Antoine LEROY SOUQUE** - *Post-Master student* - [GitHub](https://github.com/PurpleBooth)
