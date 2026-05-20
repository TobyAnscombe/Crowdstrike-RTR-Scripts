# Disable WFP auditing after collection - it's verbose
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
