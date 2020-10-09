#Excel must be installed on the machine

function SET-EXCELFiletoCSV {
param($xlsxfilepath,$xlsxSheetName,$csvfilepath)
$objExcel = New-Object -ComObject Excel.Application
$objExcel.Visible = $False
$objExcel.DisplayAlerts = $False
$xlsxWorkBook = $objExcel.Workbooks.Open($xlsxfilepath)
$xlsxWorkSheet = $xlsxWorkBook.sheets.item("$xlsxSheetName")

[int]$xlsxtoCSVoption = 23
$xlsxWorkSheet.SaveAs($csvfilepath,$xlsxtoCSVoption)
$objExcel.quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($objExcel)
$csvfilepath
}

SET-EXCELFiletoCSV -xlsxfilepath $path1 -xlsxSheetName $arbeitsblattname  -csvfilepath $path2
