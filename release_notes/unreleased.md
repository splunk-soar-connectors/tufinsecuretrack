**Unreleased**

* Enable TLS certificate verification by default while retaining an explicit opt-out. [PSAAS-30761]
* Escape action parameters before embedding them in display-view JavaScript. [PSAAS-30871]
* Bound API response sizes and reject unsafe XML declarations before parsing. [PSAAS-31983]
* Bound network-object pagination and fail when the API stops making progress. [PSAAS-32146]
* Evaluate connectivity from each device's first matching rule and recognize explicit permit and block actions. [PSAAS-32113]
* Report an IP as blocked only when every device's first matching rule blocks it. [PSAAS-32307]
