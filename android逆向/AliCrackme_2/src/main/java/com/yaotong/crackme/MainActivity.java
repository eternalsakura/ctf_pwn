package com.yaotong.crackme;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends Activity {
    public Button btn_submit;
    public EditText inputCode;

    public native boolean securityCheck(String str);

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        getWindow().setBackgroundDrawableResource(R.drawable.bg);
        this.inputCode = (EditText) findViewById(R.id.inputcode);
        this.btn_submit = (Button) findViewById(R.id.submit);
        this.btn_submit.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (MainActivity.this.securityCheck(MainActivity.this.inputCode.getText().toString())) {
                    MainActivity.this.startActivity(new Intent(MainActivity.this, ResultActivity.class));
                    return;
                }
                Toast.makeText(MainActivity.this.getApplicationContext(), "验证码校验失败", 0).show();
            }
        });
    }

    static {
        System.loadLibrary("crackme");
    }
}
