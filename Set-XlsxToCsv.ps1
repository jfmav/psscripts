<#
.SYNOPSIS
    auto Convert Excel to CSV
.DESCRIPTION
Open Excel over ComObject --> Excel must be installed on Machine

.NOTES
    Name:        Set-XlsxToCsv.ps1
    Author:      JFmav
    Created:     2020-10-09
    Version:     0.3
#>

function SET-EXCELFiletoCSV {
param($xlsxfilepath,$xlsxSheetName,$csvfilepath)
#open excel-file
$objExcel = New-Object -ComObject Excel.Application
$objExcel.Visible = $False
$objExcel.DisplayAlerts = $False
$xlsxWorkBook = $objExcel.Workbooks.Open($xlsxfilepath)
$xlsxWorkSheet = $xlsxWorkBook.sheets.item("$xlsxSheetName")

#convert
#Convert Option CSV=23
[int]$xlsxtoCSVoption = 23
$xlsxWorkSheet.SaveAs($csvfilepath,$xlsxtoCSVoption)
$objExcel.quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($objExcel)

#Output csvfilepath
$csvfilepath
}

SET-EXCELFiletoCSV -xlsxfilepath $path1 -xlsxSheetName $arbeitsblattname  -csvfilepath $path2
