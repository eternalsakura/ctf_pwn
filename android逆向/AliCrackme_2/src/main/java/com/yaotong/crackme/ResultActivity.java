package com.yaotong.crackme;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class ResultActivity extends Activity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("Congratulations!!!You Win!!");
        setContentView(tv);
    }
}
