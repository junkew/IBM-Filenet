Within ACCE menu events,actions,processes --> Search Function Defintions
There you can add a new javascript function like below that formats dates

```    
function getFunctionName() {
    return "cmCustom::FormatDate";
}

function requiresTransaction() {
    return false;
}

function validate(sfd, paramTypes) {
    if (paramTypes.length != 2) {
        throw "cmCustom::FormatDate requires exactly 2 parameters: a Date and a format string or rounding integer.";
    }

    if (paramTypes[0] != java.util.Date) {
        throw "First parameter must be a java.util.Date.";
    }

    var type2 = paramTypes[1];
    if (type2 != java.lang.String && type2 != java.lang.Integer && type2 != java.lang.Double && type2 != java.lang.Long) {
        throw "Second parameter must be either a format String or an Integer (0–60) for rounding.";
    }

    return java.lang.String;
}

function evaluate(sfd, params) {
    var date = params[0];
    var formatOrRounding = params[1];

    if (date == null || formatOrRounding == null) return null;

    var sdf;
    var roundingMinutes = 0;

    // Check if formatOrRounding is a number
    if (formatOrRounding instanceof java.lang.Number) {
        roundingMinutes = formatOrRounding.intValue();
        if (roundingMinutes > 0 && roundingMinutes <= 60) {
            var millis = date.getTime();
            var roundMillis = roundingMinutes * 60 * 1000;
            millis = Math.round(millis / roundMillis) * roundMillis;
            date = new java.util.Date(millis);
        }
        sdf = new java.text.SimpleDateFormat("yyyy-MM-dd-HH:mm");
    } else {
        // Assume it's a format string
        sdf = new java.text.SimpleDateFormat(formatOrRounding);
    }

    return sdf.format(date);
}

```

And then you can use it in a straight forward ACCE Search SQL
```
SELECT [This], cmCustom::FormatDate(dateCreated, 'yyyy-MM-dd HH:mm') as formattedDate
FROM [Document] 
OPTIONS(TIMELIMIT 180,COUNT_LIMIT 1000)
```
or 
with an interval of 5,10,15,30 (or any usefull  number >0 <=60
```
SELECT [This], cmCustom::FormatDate(dateCreated, 15) as formattedDate
FROM [Document] 
OPTIONS(TIMELIMIT 180,COUNT_LIMIT 1000)
```

