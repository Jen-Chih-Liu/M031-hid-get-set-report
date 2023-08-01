// hid_control_set_get_report.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "windows.h"
extern "C" {

	// This file is in the Windows DDK available from Microsoft.
#include "hidsdi.h"

#include "setupapi.h"
#include <dbt.h>
}

HIDP_CAPS							Capabilities;
PSP_DEVICE_INTERFACE_DETAIL_DATA	detailData;
HANDLE								DeviceHandle;
DWORD								dwError;
HANDLE								hEventObject;
HANDLE								hDevInfo;
GUID								HidGuid;
OVERLAPPED							HIDOverlapped;
char								InputReport[256];
ULONG								Length;
LPOVERLAPPED						lpOverLap;
bool								MyDeviceDetected = FALSE;
DWORD								NumberOfBytesRead;
char								OutputReport[256];
HANDLE								ReadHandle;
ULONG								Required;
HANDLE								WriteHandle;


int VendorID = 0x0416;
int ProductID = 0x5020;
bool ConnectHID(void)
{
	//Use a series of API calls to find a HID with a specified Vendor IF and Product ID.

	HIDD_ATTRIBUTES						Attributes;
	DWORD								DeviceUsage;
	SP_DEVICE_INTERFACE_DATA			devInfoData;
	bool								LastDevice = FALSE;
	int									MemberIndex = 0;
	LONG								Result;


	Length = 0;
	detailData = NULL;
	DeviceHandle = NULL;

	/*
	API function: HidD_GetHidGuid
	Get the GUID for all system HIDs.
	Returns: the GUID in HidGuid.
	*/

	HidD_GetHidGuid(&HidGuid);

	/*
	API function: SetupDiGetClassDevs
	Returns: a handle to a device information set for all installed devices.
	Requires: the GUID returned by GetHidGuid.
	*/

	hDevInfo = SetupDiGetClassDevs
	(&HidGuid,
		NULL,
		NULL,
		DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);

	devInfoData.cbSize = sizeof(devInfoData);

	//Step through the available devices looking for the one we want. 
	//Quit on detecting the desired device or checking all available devices without success.

	MemberIndex = 0;
	LastDevice = FALSE;

	do
	{
		/*
		API function: SetupDiEnumDeviceInterfaces
		On return, MyDeviceInterfaceData contains the handle to a
		SP_DEVICE_INTERFACE_DATA structure for a detected device.
		Requires:
		The DeviceInfoSet returned in SetupDiGetClassDevs.
		The HidGuid returned in GetHidGuid.
		An index to specify a device.
		*/

		Result = SetupDiEnumDeviceInterfaces
		(hDevInfo,
			0,
			&HidGuid,
			MemberIndex,
			&devInfoData);

		if (Result != 0)
		{
			//A device has been detected, so get more information about it.

			/*
			API function: SetupDiGetDeviceInterfaceDetail
			Returns: an SP_DEVICE_INTERFACE_DETAIL_DATA structure
			containing information about a device.
			To retrieve the information, call this function twice.
			The first time returns the size of the structure in Length.
			The second time returns a pointer to the data in DeviceInfoSet.
			Requires:
			A DeviceInfoSet returned by SetupDiGetClassDevs
			The SP_DEVICE_INTERFACE_DATA structure returned by SetupDiEnumDeviceInterfaces.

			The final parameter is an optional pointer to an SP_DEV_INFO_DATA structure.
			This application doesn't retrieve or use the structure.
			If retrieving the structure, set
			MyDeviceInfoData.cbSize = length of MyDeviceInfoData.
			and pass the structure's address.
			*/

			//Get the Length value.
			//The call will return with a "buffer too small" error which can be ignored.

			Result = SetupDiGetDeviceInterfaceDetail
			(hDevInfo,
				&devInfoData,
				NULL,
				0,
				&Length,
				NULL);

			//Allocate memory for the hDevInfo structure, using the returned Length.

			detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(Length);

			//Set cbSize in the detailData structure.

			detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

			//Call the function again, this time passing it the returned buffer size.

			Result = SetupDiGetDeviceInterfaceDetail
			(hDevInfo,
				&devInfoData,
				detailData,
				Length,
				&Required,
				NULL);

			// Open a handle to the device.
			// To enable retrieving information about a system mouse or keyboard,
			// don't request Read or Write access for this handle.

			/*
			API function: CreateFile
			Returns: a handle that enables reading and writing to the device.
			Requires:
			The DevicePath in the detailData structure
			returned by SetupDiGetDeviceInterfaceDetail.
			*/

			DeviceHandle = CreateFile
			(detailData->DevicePath,
				0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				(LPSECURITY_ATTRIBUTES)NULL,
				OPEN_EXISTING,
				0,
				NULL);

			/*
			API function: HidD_GetAttributes
			Requests information from the device.
			Requires: the handle returned by CreateFile.
			Returns: a HIDD_ATTRIBUTES structure containing
			the Vendor ID, Product ID, and Product Version Number.
			Use this information to decide if the detected device is
			the one we're looking for.
			*/

			//Set the Size to the number of bytes in the structure.

			Attributes.Size = sizeof(Attributes);

			Result = HidD_GetAttributes
			(DeviceHandle,
				&Attributes);

			//Is it the desired device?

			MyDeviceDetected = FALSE;

			if (Attributes.VendorID == VendorID)
			{
				if (Attributes.ProductID == ProductID)
				{
					//Both the Vendor ID and Product ID match.

					MyDeviceDetected = TRUE;
					//MyDevicePathName = detailData->DevicePath;
					//printf("Device detected");

					//Register to receive device notifications.

					//RegisterForDeviceNotifications();

					//Get the device's capablities.

					//Get the Capabilities structure for the device.
					PHIDP_PREPARSED_DATA	PreparsedData;

					/*
					API function: HidD_GetPreparsedData
					Returns: a pointer to a buffer containing the information about the device's capabilities.
					Requires: A handle returned by CreateFile.
					There's no need to access the buffer directly,
					but HidP_GetCaps and other API functions require a pointer to the buffer.
					*/

					HidD_GetPreparsedData(DeviceHandle, &PreparsedData);

					/*
					API function: HidP_GetCaps
					Learn the device's capabilities.
					For standard devices such as joysticks, you can find out the specific
					capabilities of the device.
					For a custom device, the software will probably know what the device is capable of,
					and the call only verifies the information.
					Requires: the pointer to the buffer returned by HidD_GetPreparsedData.
					Returns: a Capabilities structure containing the information.
					*/

					HidP_GetCaps(PreparsedData, &Capabilities);
					HidD_FreePreparsedData(PreparsedData);

					// 利用HID Report Descriptor來辨識HID Transfer裝置   
					DeviceUsage = (Capabilities.UsagePage * 256) + Capabilities.Usage;

					if (DeviceUsage != 0xFF0001)   // Report Descriptor
						continue;

					// Get a handle for writing Output reports.
					WriteHandle = CreateFile
					(detailData->DevicePath,
						GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						(LPSECURITY_ATTRIBUTES)NULL,
						OPEN_EXISTING,
						0,
						NULL);

					// Prepare to read reports using Overlapped I/O.

					//PrepareForOverlappedTransfer();
					
						//Get a handle to the device for the overlapped ReadFiles.

						ReadHandle = CreateFile
						(detailData->DevicePath,
							GENERIC_READ,
							FILE_SHARE_READ | FILE_SHARE_WRITE,
							(LPSECURITY_ATTRIBUTES)NULL,
							OPEN_EXISTING,
							FILE_FLAG_OVERLAPPED,
							NULL);


						//Get an event object for the overlapped structure.

						/*API function: CreateEvent
						Requires:
						  Security attributes or Null
						  Manual reset (true). Use ResetEvent to set the event object's state to non-signaled.
						  Initial state (true = signaled)
						  Event object name (optional)
						Returns: a handle to the event object
						*/

						if (hEventObject == 0)
						{
							hEventObject = CreateEvent(NULL,TRUE,TRUE,"");

							//Set the members of the overlapped structure.
							HIDOverlapped.hEvent = hEventObject;
							HIDOverlapped.Offset = 0;
							HIDOverlapped.OffsetHigh = 0;
						}

				} //if (Attributes.ProductID == ProductID)

				else
					//The Product ID doesn't match.

					CloseHandle(DeviceHandle);

			} //if (Attributes.VendorID == VendorID)

			else
				//The Vendor ID doesn't match.

				CloseHandle(DeviceHandle);

			//Free the memory used by the detailData structure (no longer needed).

			free(detailData);

		}  //if (Result != 0)

		else
			//SetupDiEnumDeviceInterfaces returned 0, so there are no more devices to check.
			LastDevice = TRUE;

		//If we haven't found the device yet, and haven't tried every available device,
		//try the next one.

		MemberIndex = MemberIndex + 1;

	} //do

	while ((LastDevice == FALSE) && (MyDeviceDetected == FALSE));

	if (MyDeviceDetected == FALSE)
		printf("Device not detected\n\r");
	else
		printf("Device detected\n\r");

	//Free the memory reserved for hDevInfo by SetupDiClassDevs.
	SetupDiDestroyDeviceInfoList(hDevInfo);

	return MyDeviceDetected;
}

void CloseHandles(void )
{
	//Close open handles.

	if (DeviceHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(DeviceHandle);
	}

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ReadHandle);
	}

	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(WriteHandle);
	}
}
void WriteOutputReport(void)
{
	//Send a report to the device.

	DWORD	BytesWritten = 0;
	INT		Index = 0;
	ULONG	Result;
	
	INT BufSize = 0;

	for (int i = 0; i < 64; i++)
		OutputReport[i] = i;
	BufSize = 65;

	//Send a report to the device.

	/*
	HidD_SetOutputReport
	Sends a report to the device.
	Returns: success or failure.
	Requires:
	The device handle returned by CreateFile.
	A buffer that holds the report.
	The Output Report length returned by HidP_GetCaps,
	*/

	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		Result = HidD_SetOutputReport
		(WriteHandle,
			OutputReport,
			Capabilities.OutputReportByteLength);
	}

	if (Result)
	{
		printf("An Output report was written to the device.\n\r");
	}
	else
	{
		//The write attempt failed, so close the handles, display a message,
		//and set MyDeviceDetected to FALSE so the next attempt will look for the device.
		CloseHandles();
	}
}


void ReadInputReport(void)
{

	// Retrieve an Input report from the device.

	DWORD	Result;


	//Read a report from the device using a control transfer.

	/*
	HidD_GetInputReport
	Returns:
	True on success
	Requires:
	A device handle returned by CreateFile.
	A buffer to hold the report.
	The report length returned by HidP_GetCaps in Capabilities.InputReportByteLength.
	*/

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		Result = HidD_GetInputReport
		(ReadHandle,
			InputReport,
			Capabilities.InputReportByteLength);
	}
	else
	{
		Result = FALSE;
	}

	if (!Result)
	{
		//The read attempt failed, so close the handles, display a message,
		//and set MyDeviceDetected to FALSE so the next attempt will look for the device.
		CloseHandles();				
	}
	else
	{
		printf("Received Input report:\n\r");

		//Display the report data.
		

	}
}

int main()
{
	ConnectHID();
	WriteOutputReport();
	ReadInputReport();
	CloseHandles();
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
