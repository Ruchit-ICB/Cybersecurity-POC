# Model Evaluation Report
## Weighted Classification Metrics
Precision: 0.800
Recall:    0.600
F1 Score:  0.667

## Detailed Classification Report
                                     precision    recall  f1-score   support

         Brute-Force Authentication       1.00      0.50      0.67         2
Cloud Metadata Service Abuse (IMDS)       0.00      0.00      0.00         0
         Cross-Site Scripting (XSS)       1.00      1.00      1.00         1
                      SQL Injection       1.00      1.00      1.00         1
 Server-Side Request Forgery (SSRF)       0.00      0.00      0.00         1
                             benign       0.00      0.00      0.00         0

                           accuracy                           0.60         5
                          macro avg       0.50      0.42      0.44         5
                       weighted avg       0.80      0.60      0.67         5

## Confusion Matrix
|                                     |   Brute-Force Authentication |   Cloud Metadata Service Abuse (IMDS) |   Cross-Site Scripting (XSS) |   SQL Injection |   Server-Side Request Forgery (SSRF) |   benign |
|:------------------------------------|-----------------------------:|--------------------------------------:|-----------------------------:|----------------:|-------------------------------------:|---------:|
| Brute-Force Authentication          |                            1 |                                     0 |                            0 |               0 |                                    0 |        1 |
| Cloud Metadata Service Abuse (IMDS) |                            0 |                                     0 |                            0 |               0 |                                    0 |        0 |
| Cross-Site Scripting (XSS)          |                            0 |                                     0 |                            1 |               0 |                                    0 |        0 |
| SQL Injection                       |                            0 |                                     0 |                            0 |               1 |                                    0 |        0 |
| Server-Side Request Forgery (SSRF)  |                            0 |                                     1 |                            0 |               0 |                                    0 |        0 |
| benign                              |                            0 |                                     0 |                            0 |               0 |                                    0 |        0 |