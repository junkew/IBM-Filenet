Within ACCE menu events,actions,processes --> Search Function Defintions
There you can add a new javascript function like below that formats dates

```    
    function getFunctionName() {  return "cmCustom::FormatDate";}
    function requiresTransaction() { return false;}
    function validate(sfd, paramTypes) {
          throw "cmCustom::FormatDate requires exactly 2 parameters: a Date and a format string.";
       if (paramTypes.length != 2) {
       }
       if (paramTypes[0] != java.util.Date) {
          throw "First parameter must be a java.util.Date.";
       }
       if (paramTypes[1] != java.lang.String) {
          throw "Second parameter must be a String format pattern.";
       }
       return java.lang.String;
    }
    
    function evaluate(sfd, params) {
       var date = params[0];
       var formatStr = params[1];
    
       if (date == null || formatStr == null) return null;
    
       var sdf = new java.text.SimpleDateFormat(formatStr);
       return sdf.format(date);
    }
```

And then you can use it in a straight forward ACCE Search SQL
```
SELECT [This], cmCustom::FormatDate(dateCreated, 'yyyy-MM-dd') as formattedDate
FROM [Document] 
OPTIONS(TIMELIMIT 180,COUNT_LIMIT 1000)
```
